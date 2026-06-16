package com.nfc.wallet

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.util.Log
import org.json.JSONObject

/**
 * NfcReaderHelper — PSA rolü NFC okuyucu katmanı + Payload Doğrulaması
 *
 * İletişim sırası:
 *   1. CPA cihazı yaklaştırılır → onTagDiscovered()
 *   2. IsoDep bağlanır (timeout: 15 sn)
 *   3. SELECT AID → 90 00 beklenir
 *   4. GET DATA → payload + 90 00 alınır
 *   5. validatePayload() → format doğrulanır
 *   6. Payload callback ile PsaActivity'e iletilir
 *
 * ─── Payload Doğrulama Katmanı ───────────────────────────────────────────────
 * validatePayload() iki formatı kabul eder:
 *
 *   Güvensiz format: { "cardNumber", "amount", "currency" }
 *   Güvenli format:  { "iv", "ciphertext", "hmac" }
 *
 * Format tanınmıyorsa payload reddedilir ve onError çağrılır.
 * Bu kontrol, sahte/hatalı APDU yanıtlarını erken tespit eder.
 *
 * ─── Log Etiketleri ─────────────────────────────────────────────────────────
 * PERF_STATS    : NFC SELECT ve GET DATA süreleri
 * NFC_VALIDATE  : Payload format doğrulama sonuçları
 */
class NfcReaderHelper(
    private val onPayloadReceived: (rawBytes: ByteArray, rawHex: String) -> Unit,
    private val onError: (String) -> Unit
) : NfcAdapter.ReaderCallback {

    companion object {
        private const val TAG          = "NfcReader"
        private const val VALIDATE_TAG = "NFC_VALIDATE"

        // CPA ile aynı AID — apdu_service.xml ile eşleşmeli
        private val SELECT_AID_APDU = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            0x07.toByte(),
            0xF0.toByte(), 0x39.toByte(), 0x41.toByte(), 0x48.toByte(),
            0x14.toByte(), 0x10.toByte(), 0x00.toByte()
        )

        private val GET_DATA_APDU = byteArrayOf(
            0x80.toByte(), 0xCA.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        private val SW_OK = byteArrayOf(0x90.toByte(), 0x00.toByte())

        // Güvensiz mod için zorunlu JSON alanları
        private val INSECURE_REQUIRED_FIELDS = setOf("cardNumber", "amount")

        // Güvenli mod için zorunlu JSON alanları
        private val SECURE_REQUIRED_FIELDS = setOf("iv", "ciphertext", "hmac")

        // Payload boyutu limitleri (byte)
        private const val MIN_PAYLOAD_SIZE = 10
        private const val MAX_PAYLOAD_SIZE = 4096
    }

    override fun onTagDiscovered(tag: Tag?) {
        Log.d(TAG, "NFC tag algılandı")

        val isoDep = IsoDep.get(tag) ?: run {
            Log.e(TAG, "IsoDep alınamadı — uyumsuz NFC tipi")
            onError("Desteklenmeyen NFC tipi. CPA uygulamasını açın.")
            return
        }

        try {
            isoDep.connect()
            isoDep.timeout = 15_000

            // ── ADIM 1: SELECT AID ──────────────────────────────────────────
            val t0Nfc    = System.nanoTime()
            val t0Select   = System.nanoTime()
            val selectResp = isoDep.transceive(SELECT_AID_APDU)
            val selectMs   = (System.nanoTime() - t0Select) / 1_000_000.0
            PerformanceTracker.record("NFC_SELECT", selectMs)
            Log.i("PERF_STATS", "NFC_SELECT: ${"%.4f".format(selectMs)} ms")
            Log.d(TAG, "SELECT yanıtı: ${selectResp.toHexString()}")

            if (!selectResp.endsWith(SW_OK)) {
                onError("SELECT AID başarısız: ${selectResp.toHexString()}")
                return
            }

            // ── ADIM 2: GET DATA ─────────────────────────────────────────────
            val t0Get    = System.nanoTime()
            val dataResp = isoDep.transceive(GET_DATA_APDU)
            val getMs    = (System.nanoTime() - t0Get) / 1_000_000.0
            val totalNfcMs = (System.nanoTime() - t0Nfc) / 1_000_000.0
            PerformanceTracker.record("NFC_GET_DATA", getMs)
            PerformanceTracker.record("NFC_TOTAL",    totalNfcMs)
            Log.i("PERF_STATS", "NFC_GET_DATA: ${"%.4f".format(getMs)} ms | ${dataResp.size} bytes")
            Log.i("PERF_STATS", "NFC_TOTAL:    ${"%.4f".format(totalNfcMs)} ms")
            Log.d(TAG, "GET DATA yanıtı: ${dataResp.size} bytes")

            if (dataResp.size < 2 || !dataResp.endsWith(SW_OK)) {
                onError("Veri alımı başarısız: ${dataResp.toHexString()}")
                return
            }

            // SW_OK (son 2 byte) çıkarılır
            val payloadBytes = dataResp.copyOfRange(0, dataResp.size - 2)
            val rawHex       = dataResp.toHexString()

            // ── ADIM 3: Payload Format Doğrulama ─────────────────────────────
            val validationResult = validatePayload(payloadBytes)
            if (!validationResult.isValid) {
                Log.e(TAG, "Payload doğrulama başarısız: ${validationResult.error}")
                Log.e(VALIDATE_TAG, "INVALID_PAYLOAD | error=${validationResult.error} | size=${payloadBytes.size}")
                onError("Geçersiz payload: ${validationResult.error}")
                return
            }

            Log.i(VALIDATE_TAG, "VALID_PAYLOAD | format=${validationResult.format} | size=${payloadBytes.size} bytes")
            Log.d(TAG, "Payload doğrulandı — PsaActivity'e iletiliyor")

            onPayloadReceived(payloadBytes, rawHex)

        } catch (e: android.nfc.TagLostException) {
            Log.e(TAG, "Tag lost", e)
            onError("Bağlantı kesildi. Cihazları sabit tutun ve tekrar deneyin.")
        } catch (e: java.io.IOException) {
            Log.e(TAG, "IO hatası", e)
            onError("NFC IO hatası: ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "NFC hatası", e)
            onError("NFC hatası: ${e.message}")
        } finally {
            try { isoDep.close() } catch (_: Exception) {}
        }
    }

    // ── Payload Doğrulama ─────────────────────────────────────────────────────

    /**
     * Alınan NFC payload'ının format geçerliliğini doğrular.
     *
     * Kontroller:
     *   1. Boyut sınırları (10 byte – 4096 byte)
     *   2. Geçerli UTF-8 metin
     *   3. Geçerli JSON yapısı
     *   4. Güvensiz format: {"cardNumber", "amount"} alanları mevcut
     *      VEYA Güvenli format: {"iv", "ciphertext", "hmac"} alanları mevcut
     *
     * @param bytes Ham payload byte dizisi
     * @return ValidationResult (isValid, format, error)
     */
    private fun validatePayload(bytes: ByteArray): ValidationResult {

        // Kontrol 1: Boyut
        if (bytes.size < MIN_PAYLOAD_SIZE) {
            return ValidationResult(false, "UNKNOWN", "Payload çok küçük (${bytes.size} < $MIN_PAYLOAD_SIZE bytes)")
        }
        if (bytes.size > MAX_PAYLOAD_SIZE) {
            return ValidationResult(false, "UNKNOWN", "Payload çok büyük (${bytes.size} > $MAX_PAYLOAD_SIZE bytes)")
        }

        // Kontrol 2: UTF-8 metin
        val text = try {
            String(bytes, Charsets.UTF_8)
        } catch (e: Exception) {
            return ValidationResult(false, "UNKNOWN", "UTF-8 decode hatası: ${e.message}")
        }

        // Kontrol 3: JSON yapısı
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            return ValidationResult(false, "UNKNOWN", "Geçersiz JSON: ${e.message}")
        }

        // Kontrol 4a: Güvensiz format
        if (INSECURE_REQUIRED_FIELDS.all { json.has(it) }) {
            val cardNumber = json.optString("cardNumber", "")
            val amount     = json.optString("amount", "")

            if (cardNumber.isBlank()) {
                return ValidationResult(false, "INSECURE", "cardNumber boş olamaz")
            }
            if (amount.isBlank()) {
                return ValidationResult(false, "INSECURE", "amount boş olamaz")
            }

            Log.d(TAG, "Güvensiz format doğrulandı — cardNumber=${cardNumber.take(4)}xxxx")
            return ValidationResult(true, "INSECURE")
        }

        // Kontrol 4b: Güvenli (şifreli) format
        if (SECURE_REQUIRED_FIELDS.all { json.has(it) }) {
            val iv         = json.optString("iv", "")
            val ciphertext = json.optString("ciphertext", "")
            val hmac       = json.optString("hmac", "")

            if (iv.isBlank() || ciphertext.isBlank() || hmac.isBlank()) {
                return ValidationResult(false, "SECURE", "Şifreli zarfta boş alan var (iv/ciphertext/hmac)")
            }

            if (iv.length < 16) {
                return ValidationResult(false, "SECURE", "IV çok kısa — geçersiz AES IV")
            }

            // cpa_perf alanı opsiyoneldir — varsa CPA timing verisi taşır
            val hasCpaPerf = json.has("cpa_perf")
            Log.d(TAG, "Güvenli format doğrulandı — iv_len=${iv.length} ct_len=${ciphertext.length} cpa_perf=$hasCpaPerf")
            return ValidationResult(true, "SECURE")
        }

        return ValidationResult(false, "UNKNOWN", "Tanınmayan payload formatı — beklenen alanlar yok")
    }

    // ── Veri Sınıfları ────────────────────────────────────────────────────────

    private data class ValidationResult(
        val isValid: Boolean,
        val format:  String,
        val error:   String = ""
    )

    // ── Extension Fonksiyonlar ────────────────────────────────────────────────

    private fun ByteArray.toHexString() = joinToString(" ") { "%02X".format(it) }

    private fun ByteArray.endsWith(suffix: ByteArray): Boolean {
        if (size < suffix.size) return false
        return suffix.indices.all { this[size - suffix.size + it] == suffix[it] }
    }
}
