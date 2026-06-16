package com.nfc.wallet

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// ── Veri Modelleri ────────────────────────────────────────────────────────────

data class PaymentData(
    val cardNumber: String,
    val amount:     String,
    val currency:   String,
    val token:      String?  = null,
    val timestamp:  Long?    = null,
    val tampered:   Boolean  = false
)

sealed class PaymentResult {
    data class Success(val data: PaymentData, val note: String = "") : PaymentResult()
    data class Failure(val reason: String)                           : PaymentResult()
}

// ── CryptoHelper ──────────────────────────────────────────────────────────────

/**
 * CryptoHelper — Ortak Kriptografi Yardımcısı
 *
 * Tüm işlem adımlarının süreleri PerformanceTracker'a kaydedilir:
 *
 * CPA buildSecurePayload():
 *   CPA_DATA_PREP    → İç JSON oluşturma
 *   CPA_AES_ENCRYPT  → AES-256-CBC şifreleme
 *   CPA_HMAC_COMPUTE → HMAC-SHA256 hesaplama
 *   CPA_TOTAL_BUILD  → Toplam payload üretim süresi
 *
 * PSA processSecurePayload():
 *   PSA_HMAC_VERIFY  → HMAC doğrulama
 *   PSA_AES_DECRYPT  → AES şifre çözme
 *   PSA_TOKEN_CHECK  → Timestamp + Token kontrolü
 *   PSA_TOTAL_VERIFY → Toplam PSA doğrulama
 *   E2E_REAL_CPA     → CPA t0'dan itibaren uçtan uca gerçek süre
 */
object CryptoHelper {

    private const val TAG = "CryptoHelper"

    // Anahtarlar KeyManager üzerinden alınır — hardcoded değerler bu sınıfta YOK
    private val aesKeyBytes  get() = KeyManager.getAesKeyBytes()
    private val hmacKeyBytes get() = KeyManager.getHmacKeyBytes()

    private const val TIMESTAMP_WINDOW_MS = 30_000L

    // ═════════════════════════════════════════════════════════════════════════
    //  CPA — AŞAMA 1: GÜVENSİZ PAYLOAD
    // ═════════════════════════════════════════════════════════════════════════

    fun buildInsecurePayload(cardNumber: String, amount: String, tampered: Boolean): String {
        PerformanceTracker.start("CPA_DATA_PREP")

        val t0 = System.nanoTime()
        val obj = JSONObject().apply {
            put("cardNumber", cardNumber)
            put("amount",     amount)
            put("currency",   "TL")
            put("tampered",   tampered)
            put("cpa_t0",     t0)
        }
        val json = obj.toString()

        val buildMs = PerformanceTracker.stop("CPA_DATA_PREP")
        PerformanceTracker.record("CPA_TOTAL_BUILD", buildMs, "INSECURE")

        Log.i("PERF_STATS",    "CPA_INSECURE_DATA_PREP: ${"%.4f".format(buildMs)} ms")
        Log.i("PERF_STATS",    "CPA_INSECURE_TOTAL_BUILD: ${"%.4f".format(buildMs)} ms | ${json.toByteArray().size} bytes")
        Log.i("ATTACK_MATRIX", "scenario=EAVESDROPPING | mechanism=NONE | result=PLAINTEXT_SENT")
        Log.d(TAG,             "[EAVESDROPPING] Payload: $json")

        return json
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  CPA — AŞAMA 2: GÜVENLİ PAYLOAD
    // ═════════════════════════════════════════════════════════════════════════

    fun buildSecurePayload(cardNumber: String, amount: String): String {
        val t0 = System.nanoTime()

        // ── 1. İç JSON ───────────────────────────────────────────────────────
        PerformanceTracker.start("CPA_DATA_PREP")
        val inner = JSONObject().apply {
            put("cardNumber", cardNumber)
            put("amount",     amount)
            put("currency",   "TL")
            put("token",      UUID.randomUUID().toString())
            put("timestamp",  System.currentTimeMillis())
            put("cpa_t0",     t0)
        }
        val plaintext = inner.toString()
        val dataPrepMs = PerformanceTracker.stop("CPA_DATA_PREP")

        // ── 2. AES-256-CBC Şifreleme ──────────────────────────────────────────
        PerformanceTracker.start("CPA_AES_ENCRYPT")
        val cipher  = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKeyBytes, "AES"))
        val iv         = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val ivB64      = Base64.encodeToString(iv,         Base64.NO_WRAP)
        val ctB64      = Base64.encodeToString(ciphertext, Base64.NO_WRAP)
        val aesMs = PerformanceTracker.stop("CPA_AES_ENCRYPT")

        // ── 3. HMAC-SHA256 ────────────────────────────────────────────────────
        PerformanceTracker.start("CPA_HMAC_COMPUTE")
        val dataToMac = "$ivB64.$ctB64"
        val mac       = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(hmacKeyBytes, "HmacSHA256"))
        val hmacB64   = Base64.encodeToString(
            mac.doFinal(dataToMac.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP
        )
        val hmacMs = PerformanceTracker.stop("CPA_HMAC_COMPUTE")

        // ── 4. Dış Zarf — CPA timing'leri de gömülür ──────────────────────────
        val totalMs = (System.nanoTime() - t0) / 1_000_000.0
        PerformanceTracker.record("CPA_TOTAL_BUILD", totalMs, "SECURE")

        val envelope = JSONObject().apply {
            put("iv",         ivB64)
            put("ciphertext", ctB64)
            put("hmac",       hmacB64)
            // CPA tarafının zamanlama verileri — PSA'nın Logcat'inde görünmesi için
            put("cpa_perf", JSONObject().apply {
                put("data_prep_ms",  dataPrepMs)
                put("aes_ms",        aesMs)
                put("hmac_ms",       hmacMs)
                put("total_build_ms",totalMs)
            })
        }
        val result = envelope.toString()

        Log.i("PERF_STATS", "CPA_SECURE_DATA_PREP:    ${"%.4f".format(dataPrepMs)} ms")
        Log.i("PERF_STATS", "CPA_SECURE_AES_ENCRYPT:  ${"%.4f".format(aesMs)} ms")
        Log.i("PERF_STATS", "CPA_SECURE_HMAC_COMPUTE: ${"%.4f".format(hmacMs)} ms")
        Log.i("PERF_STATS", "CPA_SECURE_TOTAL_BUILD:  ${"%.4f".format(totalMs)} ms | ${result.toByteArray().size} bytes")

        return result
    }

    fun corruptCiphertext(securePayload: String): String {
        return try {
            val json = JSONObject(securePayload)
            val ct   = json.getString("ciphertext")
            if (ct.length < 2) return securePayload
            val corrupted = ct[1].toString() + ct[0].toString() + ct.substring(2)
            json.put("ciphertext", corrupted)
            json.toString()
        } catch (e: Exception) { securePayload }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  PSA — AŞAMA 1: GÜVENSİZ İŞLEME
    // ═════════════════════════════════════════════════════════════════════════

    fun processInsecurePayload(json: String): PaymentResult {
        PerformanceTracker.start("PSA_TOTAL_VERIFY")

        Log.d(TAG,             "[EAVESDROPPING] Received: $json")
        Log.i("ATTACK_MATRIX", "scenario=EAVESDROPPING | mechanism=PLAINTEXT_JSON | result=DATA_READABLE")

        return try {
            val obj      = JSONObject(json)
            val tampered = obj.optBoolean("tampered", false)

            if (tampered) {
                Log.w("ATTACK_MATRIX", "scenario=DATA_TAMPERING | mechanism=NONE | result=ACCEPTED_NO_PROTECTION")
            }

            // E2E — CPA'dan gelen t0 ile gerçek süre
            val cpat0 = obj.optLong("cpa_t0", -1L)
            if (cpat0 > 0) {
                val e2eMs = (System.nanoTime() - cpat0) / 1_000_000.0
                PerformanceTracker.record("E2E_REAL_CPA", e2eMs, "INSECURE")
                Log.i("PERF_STATS", "E2E_REAL_CPA: ${"%.4f".format(e2eMs)} ms (INSECURE)")
            }

            val totalMs = PerformanceTracker.stop("PSA_TOTAL_VERIFY")
            PerformanceTracker.record("PSA_TOTAL_VERIFY", totalMs, "INSECURE")
            Log.i("PERF_STATS", "PSA_INSECURE_TOTAL_VERIFY: ${"%.4f".format(totalMs)} ms")

            PaymentResult.Success(
                PaymentData(
                    cardNumber = obj.getString("cardNumber"),
                    amount     = obj.getString("amount"),
                    currency   = obj.optString("currency", "TL"),
                    tampered   = tampered
                ),
                note = "Güvensiz mod — doğrulama yapılmadı"
            )
        } catch (e: Exception) {
            PerformanceTracker.stop("PSA_TOTAL_VERIFY")
            PaymentResult.Failure("JSON parse hatası: ${e.message}")
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    //  PSA — AŞAMA 2: GÜVENLİ İŞLEME
    // ═════════════════════════════════════════════════════════════════════════

    fun processSecurePayload(json: String, usedTokens: MutableSet<String>): PaymentResult {
        val t0 = System.nanoTime()

        return try {
            val envelope     = JSONObject(json)
            val ivB64        = envelope.getString("iv")
            val ctB64        = envelope.getString("ciphertext")
            val receivedHmac = envelope.getString("hmac")

            // ── ADIM 1: HMAC Doğrulama ────────────────────────────────────────
            PerformanceTracker.start("PSA_HMAC_VERIFY")
            val dataToMac    = "$ivB64.$ctB64"
            val mac          = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(hmacKeyBytes, "HmacSHA256"))
            val computedHmac = Base64.encodeToString(
                mac.doFinal(dataToMac.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP
            )
            val hmacMs = PerformanceTracker.stop("PSA_HMAC_VERIFY")
            Log.i("PERF_STATS", "PSA_SECURE_HMAC_VERIFY: ${"%.4f".format(hmacMs)} ms")

            if (computedHmac != receivedHmac) {
                Log.e("ATTACK_MATRIX", "scenario=DATA_TAMPERING | mechanism=HMAC-SHA256 | result=INTEGRITY_FAIL")
                Log.i("PERF_STATS",    "PSA_SECURE_HMAC_VERIFY: ${"%.4f".format(hmacMs)} ms (FAILED)")
                return PaymentResult.Failure("❌ HMAC Doğrulaması Başarısız — Veri Değiştirilmiş!")
            }
            Log.d(TAG, "✅ HMAC OK")

            // ── ADIM 2: AES Şifre Çözme ──────────────────────────────────────
            PerformanceTracker.start("PSA_AES_DECRYPT")
            val iv       = Base64.decode(ivB64, Base64.NO_WRAP)
            val ct       = Base64.decode(ctB64, Base64.NO_WRAP)
            val decipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            decipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(aesKeyBytes, "AES"), IvParameterSpec(iv))
            val plaintext = String(decipher.doFinal(ct), Charsets.UTF_8)
            val aesMs = PerformanceTracker.stop("PSA_AES_DECRYPT")
            Log.i("PERF_STATS", "PSA_SECURE_AES_DECRYPT: ${"%.4f".format(aesMs)} ms")

            val inner = JSONObject(plaintext)

            // ── ADIM 3: Timestamp + Token Kontrolü ───────────────────────────
            PerformanceTracker.start("PSA_TOKEN_CHECK")

            val timestamp = inner.getLong("timestamp")
            val age       = System.currentTimeMillis() - timestamp
            if (Math.abs(age) > TIMESTAMP_WINDOW_MS) {
                Log.e("ATTACK_MATRIX", "scenario=TIMESTAMP_REPLAY | result=EXPIRED age=${age}ms")
                PerformanceTracker.stop("PSA_TOKEN_CHECK")
                return PaymentResult.Failure("❌ Timestamp Süresi Dolmuş (${age / 1000}s) — Replay!")
            }

            val token = inner.getString("token")
            if (token in usedTokens) {
                Log.e("ATTACK_MATRIX", "scenario=TOKEN_REPLAY | mechanism=UUID_TOKEN | result=DUPLICATE_REJECTED")
                PerformanceTracker.stop("PSA_TOKEN_CHECK")
                return PaymentResult.Failure("❌ Duplicate Token — Replay Attack!")
            }
            usedTokens.add(token)

            val tokenMs = PerformanceTracker.stop("PSA_TOKEN_CHECK")
            Log.i("PERF_STATS", "PSA_SECURE_TOKEN_CHECK: ${"%.4f".format(tokenMs)} ms")

            // ── Toplam PSA Süresi ─────────────────────────────────────────────
            val totalMs = (System.nanoTime() - t0) / 1_000_000.0
            PerformanceTracker.record("PSA_TOTAL_VERIFY", totalMs, "SECURE")
            Log.i("PERF_STATS", "PSA_SECURE_TOTAL_VERIFY: ${"%.4f".format(totalMs)} ms")

            // ── CPA Timing — Zarftan Okunur → PSA Logcat'e Kaydedilir ─────────
            // cpa_perf alanı HMAC kapsamı dışındadır; içerik güvenli değil ama
            // performans verisi hassas değildir — sadece akademik analiz için.
            val cpaPerfObj = envelope.optJSONObject("cpa_perf")
            if (cpaPerfObj != null) {
                val cpaDataPrep = cpaPerfObj.optDouble("data_prep_ms", -1.0)
                val cpaAes      = cpaPerfObj.optDouble("aes_ms",       -1.0)
                val cpaHmac     = cpaPerfObj.optDouble("hmac_ms",      -1.0)
                val cpaTotal    = cpaPerfObj.optDouble("total_build_ms",-1.0)

                if (cpaDataPrep >= 0) PerformanceTracker.record("CPA_DATA_PREP",   cpaDataPrep, "SECURE")
                if (cpaAes      >= 0) PerformanceTracker.record("CPA_AES_ENCRYPT", cpaAes,      "SECURE")
                if (cpaHmac     >= 0) PerformanceTracker.record("CPA_HMAC_COMPUTE",cpaHmac,     "SECURE")
                if (cpaTotal    >= 0) PerformanceTracker.record("CPA_TOTAL_BUILD",  cpaTotal,    "SECURE")

                Log.i("PERF_STATS", "CPA_DATA_PREP(from_payload):   ${"%.4f".format(cpaDataPrep)} ms")
                Log.i("PERF_STATS", "CPA_AES_ENCRYPT(from_payload): ${"%.4f".format(cpaAes)} ms")
                Log.i("PERF_STATS", "CPA_HMAC(from_payload):        ${"%.4f".format(cpaHmac)} ms")
                Log.i("PERF_STATS", "CPA_TOTAL(from_payload):       ${"%.4f".format(cpaTotal)} ms")
            }

            Log.i("ATTACK_MATRIX", "scenario=NORMAL_SECURE | result=ALL_CHECKS_PASSED")

            PaymentResult.Success(
                PaymentData(
                    cardNumber = inner.getString("cardNumber"),
                    amount     = inner.getString("amount"),
                    currency   = inner.optString("currency", "TL"),
                    token      = token,
                    timestamp  = timestamp
                ),
                note = "Güvenli mod — tüm kontroller geçildi"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Güvenli payload işleme hatası", e)
            PaymentResult.Failure("İşleme hatası: ${e.message}")
        }
    }
}
