package com.nfc.wallet

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log

/**
 * PaymentHceService — HCE Kart Emülasyon Servisi (CPA rolü)
 *
 * AID: F0394148141000
 * APDU akışı:
 *   1. SELECT AID → 90 00
 *   2. GET DATA   → JSON payload + 90 00
 *
 * ─── Tamper Modu Entegrasyonu ────────────────────────────────────────────────
 * KEY_TAMPER_MODE ile seçilen saldırı türüne göre TamperHelper kullanılır:
 *
 *   GÜVENSİZ MOD:
 *     AMOUNT      → tutar 5000 TL yapılır
 *     CARD_NUMBER → son 4 hane "9999" yapılır
 *     TIMESTAMP   → 2 saat öncesine çekilir
 *     ALL_FIELDS  → hepsi birden manipüle edilir
 *
 *   GÜVENLİ MOD:
 *     Herhangi bir tamper seçilirse ciphertext bozulur → HMAC başarısız
 */
class PaymentHceService : HostApduService() {

    companion object {
        private const val TAG = "HCE"

        private val SELECT_AID_APDU = byteArrayOf(
            0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
            0x07.toByte(),
            0xF0.toByte(), 0x39.toByte(), 0x41.toByte(), 0x48.toByte(),
            0x14.toByte(), 0x10.toByte(), 0x00.toByte()
        )

        private val GET_DATA_APDU = byteArrayOf(
            0x80.toByte(), 0xCA.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte()
        )

        private val SW_OK      = byteArrayOf(0x90.toByte(), 0x00.toByte())
        private val SW_UNKNOWN = byteArrayOf(0x6F.toByte(), 0x00.toByte())

        // SharedPreferences anahtarları — CpaActivity ile paylaşılır
        const val PREF_NAME       = "nfc_wallet_prefs"
        const val KEY_SECURE      = "secure_mode"
        const val KEY_CARD        = "card_number"
        const val KEY_AMOUNT      = "amount"
        const val KEY_TAMPER_MODE = "tamper_mode_type"   // TamperMode.prefKey string'i
        const val KEY_LAST_SENT   = "last_sent_payload"
        const val KEY_CPA_ACTIVE  = "cpa_active"
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        Log.d(TAG, "APDU: ${commandApdu.toHexString()}")
        return when {
            commandApdu.startsWith(SELECT_AID_APDU) -> {
                Log.d(TAG, "SELECT AID → 90 00")
                SW_OK
            }
            commandApdu.startsWith(GET_DATA_APDU) -> {
                Log.d(TAG, "GET DATA → payload üretiliyor")
                buildAndSendPayload()
            }
            else -> {
                Log.w(TAG, "Bilinmeyen APDU")
                SW_UNKNOWN
            }
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "HCE deactivated: $reason")
    }

    // ── Payload Üretimi ───────────────────────────────────────────────────────

    /**
     * SharedPreferences'tan ayarları okur, TamperHelper ile saldırıyı uygular
     * ve payload'ı NFC APDU yanıtı olarak döndürür.
     *
     * Akış:
     *  1. Ayarları oku (kart no, tutar, mod, tamper türü)
     *  2. Temel payload üret (güvenli / güvensiz)
     *  3. Tamper uygula (TamperHelper)
     *  4. Son payload'ı SharedPreferences'a kaydet (CpaActivity logu için)
     *  5. bytes + SW_OK döndür
     */
    private fun buildAndSendPayload(): ByteArray {
        val prefs = getSharedPreferences(PREF_NAME, MODE_PRIVATE)

        if (!prefs.getBoolean(KEY_CPA_ACTIVE, false)) {
            Log.d(TAG, "CPA pasif — payload gönderilmiyor")
            return SW_UNKNOWN
        }

        val secureMode  = prefs.getBoolean(KEY_SECURE, false)
        val cardNumber  = prefs.getString(KEY_CARD, "4111 1111 1111 1111") ?: "4111 1111 1111 1111"
        val amount      = prefs.getString(KEY_AMOUNT, "100.00") ?: "100.00"
        val tamperKey   = prefs.getString(KEY_TAMPER_MODE, TamperHelper.TamperMode.NONE.prefKey)!!
        val tamperMode  = TamperHelper.TamperMode.fromPrefKey(tamperKey)
        val hasTamper   = tamperMode != TamperHelper.TamperMode.NONE

        Log.d(TAG, "Payload üretiliyor — secure=$secureMode | tamper=$tamperMode")

        val payload = when {

            // ── GÜVENLİ MOD + TAMPER ─────────────────────────────────────
            // Önce gerçek payload şifrelenir, ardından ciphertext bozulur.
            // PSA HMAC kontrolünde REDDEDER — saldırganın şifreyi değiştiremeyeceğini kanıtlar.
            secureMode && hasTamper -> {
                val original = TamperHelper.sendEncryptedData(cardNumber, amount)
                TamperHelper.corruptSecurePayload(original).also {
                    Log.w(TAG, "⚠️ TAMPER (GÜVENLİ): Ciphertext bozuldu | mod=$tamperMode")
                }
            }

            // ── GÜVENSİZ MOD + TAMPER ────────────────────────────────────
            // Düz metin JSON üretilir, seçilen alanlarda manipülasyon yapılır.
            // PSA hiçbir doğrulama yapmadan KABUL eder — tehlikeyi gösterir.
            !secureMode && hasTamper -> {
                val base = TamperHelper.sendInsecureData(cardNumber, amount, tampered = false)
                TamperHelper.tamperInsecurePayload(base, tamperMode).also {
                    Log.w(TAG, "⚠️ TAMPER (GÜVENSİZ): Veri manipüle edildi | mod=$tamperMode")
                }
            }

            // ── GÜVENLİ MOD, normal ───────────────────────────────────────
            secureMode -> TamperHelper.sendEncryptedData(cardNumber, amount)

            // ── GÜVENSİZ MOD, normal ─────────────────────────────────────
            else -> TamperHelper.sendInsecureData(cardNumber, amount)
        }

        // Son payload'ı CpaActivity'nin eavesdropping logu için sakla
        prefs.edit().putString(KEY_LAST_SENT, payload).apply()

        val payloadBytes = payload.toByteArray(Charsets.UTF_8)
        Log.i("PERF_STATS", "HCE_PAYLOAD_SIZE: ${payloadBytes.size} bytes | secure=$secureMode | tamper=$tamperMode")
        return payloadBytes + SW_OK
    }

    // ── Extension Fonksiyonlar ────────────────────────────────────────────────

    private fun ByteArray.toHexString() = joinToString(" ") { "%02X".format(it) }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        return prefix.indices.all { this[it] == prefix[it] }
    }
}
