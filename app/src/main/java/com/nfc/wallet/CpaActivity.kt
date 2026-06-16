package com.nfc.wallet

import android.content.SharedPreferences
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

/**
 * CpaActivity — Müşteri Ödeme Uygulaması (CPA)
 *
 * Kullanıcı bu ekranda:
 *  - Kart numarası ve tutar girer
 *  - Güvenli / Güvensiz modu seçer
 *  - Saldırı Modunu seçer (Spinner):
 *      NONE         → Saldırı yok
 *      AMOUNT       → Tutar 5000 TL yapılır
 *      CARD_NUMBER  → Kart son 4 hane "9999" yapılır
 *      TIMESTAMP    → Timestamp 2 saat geri çekilir
 *      ALL_FIELDS   → Hepsi birden manipüle edilir
 *  - "Kaydet & Hazırla" butonuna basar
 *  - Telefonu PSA cihazına yaklaştırır → HCE otomatik çalışır
 */
class CpaActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences

    private lateinit var etCardNumber:    EditText
    private lateinit var etAmount:        EditText
    private lateinit var swSecure:        Switch
    private lateinit var spinnerTamper:   Spinner
    private lateinit var tvTamperDesc:    TextView
    private lateinit var btnSave:         Button
    private lateinit var tvStatus:        TextView
    private lateinit var tvLastPayload:   TextView

    // TamperMode listesi — Spinner için
    private val tamperModes = TamperHelper.TamperMode.entries

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_cpa)

        prefs = getSharedPreferences(PaymentHceService.PREF_NAME, MODE_PRIVATE)

        bindViews()
        setupTamperSpinner()
        loadSettings()
        setupListeners()
        updateStatus()

        setCpaActive(true)
    }

    override fun onResume() {
        super.onResume()
        setCpaActive(true)
        refreshLastPayload()
    }

    override fun onPause() {
        super.onPause()
        setCpaActive(false)
    }

    private fun setCpaActive(active: Boolean) {
        prefs.edit().putBoolean(PaymentHceService.KEY_CPA_ACTIVE, active).apply()
    }

    // ── View Bağlama ─────────────────────────────────────────────────────────

    private fun bindViews() {
        etCardNumber  = findViewById(R.id.etCardNumber)
        etAmount      = findViewById(R.id.etAmount)
        swSecure      = findViewById(R.id.swSecure)
        spinnerTamper = findViewById(R.id.spinnerTamper)
        tvTamperDesc  = findViewById(R.id.tvTamperDesc)
        btnSave       = findViewById(R.id.btnSave)
        tvStatus      = findViewById(R.id.tvStatus)
        tvLastPayload = findViewById(R.id.tvLastPayload)
    }

    // ── Tamper Spinner Kurulumu ───────────────────────────────────────────────

    private fun setupTamperSpinner() {
        val labels = tamperModes.map { it.label }
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, labels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerTamper.adapter = adapter

        spinnerTamper.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>, view: android.view.View?, pos: Int, id: Long) {
                val mode = tamperModes[pos]
                updateTamperDescription(mode)
                updateStatus()
            }
            override fun onNothingSelected(parent: AdapterView<*>) {}
        }
    }

    private fun updateTamperDescription(mode: TamperHelper.TamperMode) {
        tvTamperDesc.text = when (mode) {
            TamperHelper.TamperMode.NONE ->
                "✅ Normal işlem — manipülasyon yok"
            TamperHelper.TamperMode.AMOUNT ->
                "⚠️ Tutar değiştirilir: Gerçek değer → 5000.00 TL\n" +
                "Güvensiz: PSA kabul eder | Güvenli: HMAC reddeder"
            TamperHelper.TamperMode.CARD_NUMBER ->
                "⚠️ Kart no son 4 hane '9999' yapılır\n" +
                "Güvensiz: PSA kabul eder | Güvenli: HMAC reddeder"
            TamperHelper.TamperMode.TIMESTAMP ->
                "⚠️ Timestamp 2 saat geri çekilir (window dışı)\n" +
                "Güvensiz: PSA kabul eder | Güvenli: Timestamp reddeder"
            TamperHelper.TamperMode.ALL_FIELDS ->
                "☠️ Kart no + Tutar + Timestamp hepsi manipüle edilir\n" +
                "Güvensiz: PSA kabul eder | Güvenli: HMAC reddeder"
        }
    }

    // ── Ayarlar ──────────────────────────────────────────────────────────────

    private fun loadSettings() {
        etCardNumber.setText(prefs.getString(PaymentHceService.KEY_CARD,   "4111 1111 1111 1111"))
        etAmount.setText(    prefs.getString(PaymentHceService.KEY_AMOUNT, "100.00"))
        swSecure.isChecked = prefs.getBoolean(PaymentHceService.KEY_SECURE, false)

        // Kaydedilmiş tamper modunu Spinner'da seç
        val savedKey = prefs.getString(PaymentHceService.KEY_TAMPER_MODE, TamperHelper.TamperMode.NONE.prefKey)!!
        val idx = tamperModes.indexOfFirst { it.prefKey == savedKey }.coerceAtLeast(0)
        spinnerTamper.setSelection(idx)
        updateTamperDescription(tamperModes[idx])
    }

    private fun saveSettings() {
        val selectedMode = tamperModes[spinnerTamper.selectedItemPosition]
        prefs.edit()
            .putString( PaymentHceService.KEY_CARD,        etCardNumber.text.toString())
            .putString( PaymentHceService.KEY_AMOUNT,      etAmount.text.toString())
            .putBoolean(PaymentHceService.KEY_SECURE,      swSecure.isChecked)
            .putString( PaymentHceService.KEY_TAMPER_MODE, selectedMode.prefKey)
            .apply()
    }

    // ── Listeners ────────────────────────────────────────────────────────────

    private fun setupListeners() {
        swSecure.setOnCheckedChangeListener { _, _ -> updateStatus() }

        btnSave.setOnClickListener {
            saveSettings()
            val mode = tamperModes[spinnerTamper.selectedItemPosition]
            tvStatus.text = buildStatusText(mode) + "\n✅ Kaydedildi — PSA cihazına yaklaştırın"
        }
    }

    // ── UI Güncelleme ─────────────────────────────────────────────────────────

    private fun updateStatus() {
        val mode = tamperModes.getOrNull(spinnerTamper.selectedItemPosition)
            ?: TamperHelper.TamperMode.NONE
        tvStatus.text = buildStatusText(mode)
        refreshLastPayload()
    }

    private fun buildStatusText(mode: TamperHelper.TamperMode): String {
        val secureLabel = if (swSecure.isChecked) "🔒 GÜVENLİ" else "⚠️ GÜVENSİZ"
        val tamperLabel = if (mode == TamperHelper.TamperMode.NONE) "Saldırı Yok" else "⚠️ ${mode.label}"
        return "$secureLabel MOD | $tamperLabel"
    }

    private fun refreshLastPayload() {
        val last = prefs.getString(PaymentHceService.KEY_LAST_SENT, "Henüz payload gönderilmedi.")
        tvLastPayload.text = last
    }
}
