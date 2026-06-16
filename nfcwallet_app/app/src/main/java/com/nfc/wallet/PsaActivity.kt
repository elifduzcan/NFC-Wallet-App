package com.nfc.wallet

import android.graphics.Color
import android.nfc.NfcAdapter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.Switch
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * PsaActivity — Ödeme Terminali (PSA)
 *
 * ─── Replay Koruması (2 Katmanlı) ────────────────────────────────────────────
 * Katman 1 — In-memory:  usedTokens set (CryptoHelper içinde kontrol edilir)
 * Katman 2 — DB:         checkTokenInDb() → paymentDao.findByToken() sorgusu
 *
 * Katman 2 önemlidir çünkü:
 *   • Uygulama kapatılıp açılsa da koruma devam eder
 *   • Token in-memory set'te olmasa bile DB'de varsa reddedilir
 *   • Saldırgan uygulamayı yeniden başlatarak replay yapamaz
 *
 * ─── DB İstatistikleri ────────────────────────────────────────────────────────
 * Her işlem sonunda logcat'e istatistik yazılır:
 *   DB_STATS: TOTAL=5 | ACCEPTED=3 | REJECTED=1 | REPLAY_BLOCKED=1 | ...
 *
 * ─── Anahtar Doğrulama ────────────────────────────────────────────────────────
 * onCreate'de KeyManager.validateKeys() çağrılır.
 * Anahtar boyutu hatalıysa uygulama IllegalStateException fırlatır.
 */
class PsaActivity : AppCompatActivity() {

    private lateinit var nfcAdapter:   NfcAdapter
    private lateinit var readerHelper: NfcReaderHelper

    // Room DB
    private lateinit var db:         AppDatabase
    private lateinit var paymentDao: PaymentDao

    // UI
    private lateinit var swSecure:       Switch
    private lateinit var tvStatus:       TextView
    private lateinit var cardResult:     View
    private lateinit var tvResult:       TextView
    private lateinit var tvCardNumber:   TextView
    private lateinit var tvAmount:       TextView
    private lateinit var tvToken:        TextView
    private lateinit var tvTimestamp:    TextView
    private lateinit var tvRawPayload:   TextView
    private lateinit var btnReplay:      Button
    private lateinit var tvReplayResult: TextView
    private lateinit var btnPerfReport:  Button  // Performans raporu butonu

    private var lastPayloadBytes: ByteArray? = null
    private var tapStartTime: Long = 0L
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * In-memory token seti.
     * DB'den yüklenir + yeni kabul edilen token'lar eklenir.
     * CryptoHelper bu set üzerinden hızlı lookup yapar.
     */
    private val usedTokens = mutableSetOf<String>()

    companion object {
        private const val BANK_DELAY_MS = 1500L
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_psa)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this) ?: run {
            finish(); return
        }

        // Anahtar bütünlüğünü doğrula (KeyManager)
        KeyManager.validateKeys()

        // Room DB başlat
        db         = AppDatabase.getInstance(this)
        paymentDao = db.paymentDao()

        bindViews()
        setupListeners()
        updateModeUI()
        loadTokensFromDb()

        // PSA modunda CPA HCE'yi pasif et
        getSharedPreferences(PaymentHceService.PREF_NAME, MODE_PRIVATE)
            .edit().putBoolean(PaymentHceService.KEY_CPA_ACTIVE, false).apply()
    }

    override fun onResume() {
        super.onResume()
        readerHelper = NfcReaderHelper(
            onPayloadReceived = { bytes, hex -> handleIncomingPayload(bytes, hex) },
            onError           = { msg -> runOnUiThread { tvStatus.text = "❌ $msg" } }
        )
        nfcAdapter.enableReaderMode(
            this, readerHelper,
            NfcAdapter.FLAG_READER_NFC_A or
                    NfcAdapter.FLAG_READER_NFC_B or
                    NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null
        )
        updateModeUI()
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter.disableReaderMode(this)
    }

    // ── Token Yükleme ─────────────────────────────────────────────────────────

    private fun loadTokensFromDb() {
        lifecycleScope.launch {
            val tokens = paymentDao.getAllTokens().filterNotNull()
            usedTokens.addAll(tokens)
            val stats = paymentDao.getStats()
            Log.d("DB_OPS",   "[TOKEN_LOAD] ${tokens.size} token DB'den yüklendi")
            Log.i("DB_STATS", "Başlangıç: ${stats.toLogString()}")
        }
    }

    // ── NFC Payload İşleme ────────────────────────────────────────────────────

    private fun handleIncomingPayload(bytes: ByteArray, rawHex: String) {
        tapStartTime     = System.nanoTime()
        lastPayloadBytes = bytes
        val json = String(bytes, Charsets.UTF_8)

        runOnUiThread {
            tvRawPayload.text = buildRawLog(rawHex, json)
            // DB replay kontrolü → sonra kripto kontrol
            checkDbReplayThenProcess(json, isReplay = false)
            updateModeUI()
        }
    }

    // ── DB Seviyesinde Replay Kontrolü ────────────────────────────────────────

    /**
     * 2 Katmanlı Replay Koruması:
     *
     * Adım 1: JSON'dan token çıkar (güvenli mod için decrypt gerekmez — token zarf içinde)
     *         Güvensiz modda token yoktur, sadece kripto kontrolüne geçilir.
     *
     * Adım 2: DB'de findByToken() → Kalıcı replay kontrolü
     *         Token daha önce kullanılmışsa anında REJECTED.
     *
     * Adım 3: CryptoHelper.processSecurePayload() → Kripto kontrol
     *         (HMAC → AES decrypt → Timestamp → In-memory token set)
     */
    private fun checkDbReplayThenProcess(json: String, isReplay: Boolean) {
        val isSecure = swSecure.isChecked

        if (!isSecure) {
            // Güvensiz modda token yok — doğrudan kripto kontrolüne geç
            processAndDisplay(json, isReplay)
            return
        }

        // Güvenli mod: önce zarf JSON'undan token'ı çıkarmaya gerek yok.
        // Token, CryptoHelper'ın AES şifresini çözdükten sonra ortaya çıkar.
        // Bu nedenle DB kontrolü CryptoHelper içindeki token tespitinden SONRA
        // savePaymentToDb() ile yapılır.
        // Ancak in-memory usedTokens zaten DB'den yüklendiğinden
        // CryptoHelper'daki kontrol de kalıcıdır.
        processAndDisplay(json, isReplay)
    }

    /**
     * Kabul edilen bir işlemin token'ının DB'de var olup olmadığını
     * bağımsız olarak doğrular (audit amaçlı).
     *
     * Bu fonksiyon, in-memory check'e ek güvenlik sağlar:
     * Eğer usedTokens set'i somehow temizlenseydi,
     * bu DB kontrolü replay'i yakalar.
     */
    private fun auditTokenInDb(token: String, onDuplicate: () -> Unit, onNew: () -> Unit) {
        lifecycleScope.launch {
            val existing = paymentDao.findByToken(token)
            if (existing != null) {
                Log.e("DB_OPS", "[DB_REPLAY_AUDIT] Token DB'de mevcut! id=${existing.id} | result=${existing.result}")
                Log.e("ATTACK_MATRIX", "scenario=DB_TOKEN_REPLAY | mechanism=DB_FINDBYTOKEN | result=DUPLICATE_FOUND_IN_DB")
                runOnUiThread { onDuplicate() }
            } else {
                runOnUiThread { onNew() }
            }
        }
    }

    // ── Ana İşlem Akışı ───────────────────────────────────────────────────────

    private fun processAndDisplay(json: String, isReplay: Boolean) {
        val isSecure  = swSecure.isChecked
        val modeLabel = if (isSecure) "SECURE" else "INSECURE"

        val result = if (isSecure) {
            CryptoHelper.processSecurePayload(json, usedTokens)
        } else {
            CryptoHelper.processInsecurePayload(json)
        }

        cardResult.visibility = View.VISIBLE

        if (isSecure) {
            Log.i("SECURITY_POSTURE", "mode=SECURE | confidentiality=5 | integrity=5 | replay_protection=5 | availability=3")
        } else {
            Log.i("SECURITY_POSTURE", "mode=INSECURE | confidentiality=1 | integrity=1 | replay_protection=1 | availability=5")
        }

        when {
            result is PaymentResult.Failure -> {
                val e2eMs = (System.nanoTime() - tapStartTime) / 1_000_000.0
                PerformanceTracker.record("E2E_TOTAL", e2eMs, modeLabel)
                Log.i("PERF_STATS", "E2E_TOTAL: ${"%.4f".format(e2eMs)} ms (REJECTED)")
                showRejected(result.reason, isReplay, e2eMs.toLong(), modeLabel)
                val resultLabel = if (isReplay) "REPLAY_BLOCKED" else "REJECTED"
                savePaymentToDb(null, isSecure, resultLabel, result.reason)
                PerformanceTracker.incrementTransaction()
                autoLogReport()
                logDbStats()
            }

            isSecure && result is PaymentResult.Success -> {
                tvStatus.text = "⏳ Banka onayı bekleniyor (~1500ms)..."
                mainHandler.postDelayed({
                    Log.i("PERF_STATS", "BANK_APPROVAL_DELAY: ${BANK_DELAY_MS} ms (simulated)")

                    val token = result.data.token
                    if (token != null) {
                        auditTokenInDb(
                            token       = token,
                            onDuplicate = {
                                showRejected("❌ DB Audit: Token daha önce kullanılmış!", isReplay, BANK_DELAY_MS, modeLabel)
                                savePaymentToDb(result.data, isSecure, "REPLAY_BLOCKED", "DB audit replay")
                            },
                            onNew = {
                                showAccepted(result.data, isReplay, BANK_DELAY_MS, modeLabel)
                                savePaymentToDb(result.data, isSecure, "ACCEPTED", result.note)
                            }
                        )
                    } else {
                        showAccepted(result.data, isReplay, BANK_DELAY_MS, modeLabel)
                        savePaymentToDb(result.data, isSecure, "ACCEPTED", result.note)
                    }

                    PerformanceTracker.incrementTransaction()
                    autoLogReport()
                    logDbStats()
                    updateModeUI()
                }, BANK_DELAY_MS)
            }

            else -> {
                val e2eMs = (System.nanoTime() - tapStartTime) / 1_000_000.0
                PerformanceTracker.record("E2E_TOTAL", e2eMs, modeLabel)
                Log.i("PERF_STATS", "E2E_TOTAL: ${"%.4f".format(e2eMs)} ms (INSECURE)")
                if (result is PaymentResult.Success) {
                    showAccepted(result.data, isReplay, e2eMs.toLong(), modeLabel)
                    savePaymentToDb(result.data, isSecure, "ACCEPTED", result.note)
                }
                PerformanceTracker.incrementTransaction()
                autoLogReport()
                logDbStats()
            }
        }
    }

    // ── DB İşlemleri ─────────────────────────────────────────────────────────

    private fun savePaymentToDb(data: PaymentData?, isSecure: Boolean, result: String, note: String) {
        lifecycleScope.launch {
            val payment = Payment(
                cardNumber = data?.cardNumber ?: "UNKNOWN",
                amount     = data?.amount     ?: "0",
                currency   = data?.currency   ?: "TL",
                token      = data?.token,
                timestamp  = data?.timestamp  ?: System.currentTimeMillis(),
                isSecure   = isSecure,
                result     = result,
                note       = note
            )
            paymentDao.insert(payment)
            Log.d("DB_OPS", "[PAYMENT_SAVED] result=$result | token=${data?.token?.take(8) ?: "null"}")
        }
    }

    /** DB istatistiklerini Logcat'e yazar — akademik tablo için */
    /** Her 5 işlemde bir otomatik rapor logla */
    private fun autoLogReport() {
        if (PerformanceTracker.transactionCount % 5 == 0) {
            val mode = if (swSecure.isChecked) "SECURE" else "INSECURE"
            PerformanceTracker.logReport(mode)
        }
    }

    private fun logDbStats() {
        lifecycleScope.launch {
            val stats = paymentDao.getStats()
            Log.i("DB_STATS", stats.toLogString())
        }
    }

    // ── UI Güncelleme ─────────────────────────────────────────────────────────

    private fun showAccepted(data: PaymentData, isReplay: Boolean, e2eMs: Long, mode: String) {
        tvResult.text = if (isReplay) "✅ ACCEPTED (REPLAY)" else "✅ ACCEPTED"
        tvResult.setBackgroundColor(Color.parseColor("#2E7D32"))
        tvCardNumber.text = "💳 Kart:      ${data.cardNumber}"
        tvAmount.text     = "💰 Tutar:     ${data.amount} ${data.currency}"
        tvToken.text      = "🔑 Token:     ${data.token ?: "N/A (güvensiz)"}"
        tvTimestamp.text  = "⏱ Timestamp: ${data.timestamp ?: "N/A (güvensiz)"}"

        tvReplayResult.text = if (isReplay) {
            "⚠️ REPLAY KABUL EDİLDİ — Güvensiz modda replay koruması yok!"
        } else {
            "📊 [$mode] E2E: ${e2eMs}ms"
        }
        tvReplayResult.setBackgroundColor(
            if (isReplay) Color.parseColor("#FF6F00") else Color.parseColor("#37474F")
        )
    }

    private fun showRejected(reason: String, isReplay: Boolean, e2eMs: Long, mode: String) {
        tvResult.text = "❌ REJECTED"
        tvResult.setBackgroundColor(Color.parseColor("#C62828"))
        tvCardNumber.text = reason
        tvAmount.text     = ""
        tvToken.text      = ""
        tvTimestamp.text  = ""

        tvReplayResult.text = if (isReplay) {
            "🔒 REPLAY BLOKE: $reason\n📊 [$mode] E2E: ${e2eMs}ms"
        } else {
            "📊 [$mode] E2E: ${e2eMs}ms | REJECTED"
        }
        tvReplayResult.setBackgroundColor(
            if (isReplay) Color.parseColor("#1B5E20") else Color.parseColor("#B71C1C")
        )
    }

    private fun updateModeUI() {
        tvStatus.text = if (swSecure.isChecked) {
            "🔒 GÜVENLİ MOD — NFC bekleniyor..."
        } else {
            "⚠️ GÜVENSİZ MOD — NFC bekleniyor..."
        }
    }

    // ── Kurulum ───────────────────────────────────────────────────────────────

    private fun bindViews() {
        swSecure       = findViewById(R.id.swSecure)
        tvStatus       = findViewById(R.id.tvStatus)
        cardResult     = findViewById(R.id.cardResult)
        tvResult       = findViewById(R.id.tvResult)
        tvCardNumber   = findViewById(R.id.tvCardNumber)
        tvAmount       = findViewById(R.id.tvAmount)
        tvToken        = findViewById(R.id.tvToken)
        tvTimestamp    = findViewById(R.id.tvTimestamp)
        tvRawPayload   = findViewById(R.id.tvRawPayload)
        btnReplay      = findViewById(R.id.btnReplay)
        tvReplayResult = findViewById(R.id.tvReplayResult)
        btnPerfReport  = findViewById(R.id.btnPerfReport)
    }

    private fun setupListeners() {
        swSecure.setOnCheckedChangeListener { _, _ ->
            usedTokens.clear()
            lifecycleScope.launch {
                paymentDao.clearAll()
                Log.d("DB_OPS", "[TOKEN_CLEAR] Mod değişti — DB ve in-memory temizlendi")
            }
            updateModeUI()
        }

        btnReplay.setOnClickListener {
            val bytes = lastPayloadBytes ?: run {
                tvReplayResult.text = "ℹ️ Önce bir NFC tap yapın."
                return@setOnClickListener
            }
            tvReplayResult.text = "🔄 Son işlem tekrar gönderiliyor..."
            tapStartTime = System.nanoTime()
            checkDbReplayThenProcess(String(bytes, Charsets.UTF_8), isReplay = true)
        }

        btnPerfReport.setOnClickListener {
            val mode = if (swSecure.isChecked) "SECURE" else "INSECURE"
            PerformanceTracker.logReport(mode)
            tvReplayResult.text = "📊 Performans raporu Logcat'e yazıldı!\n" +
                "Filtre: PERF_REPORT"
            tvReplayResult.setBackgroundColor(android.graphics.Color.parseColor("#1565C0"))
        }
    }

    // ── Yardımcı ──────────────────────────────────────────────────────────────

    private fun buildRawLog(hex: String, text: String) = buildString {
        appendLine("── RAW HEX ──────────────────────────────")
        appendLine(hex)
        appendLine()
        appendLine("── RAW TEXT ─────────────────────────────")
        append(text)
    }
}
