package com.nfc.wallet

import android.util.Log
import org.json.JSONObject

/**
 * TamperHelper — Veri Manipülasyonu Simülasyon Yardımcısı
 *
 * Gerçek saldırı senaryolarını simüle eden fonksiyonlar içerir.
 * Akademik karşılaştırma: güvensiz mod bu saldırılara karşı SAVUNMASIZ,
 * güvenli mod (HMAC + AES + Timestamp + Token) bunları ENGELLER.
 *
 * ─── Saldırı Türleri ────────────────────────────────────────────────────────
 * AMOUNT      : Tutar 100 TL → 5000 TL (fiyat manipülasyonu)
 * CARD_NUMBER : Kart numarasının son 4 hanesi → "9999" (sahte kart)
 * TIMESTAMP   : Zaman damgası 2 saat geriye çekilir (timestamp window dışı)
 * ALL_FIELDS  : Yukarıdakilerin tamamı
 *
 * Güvenli mod (secure payload) için:
 * CIPHERTEXT  : Şifreli verinin ilk 2 byte'ı yer değiştirir → HMAC geçersiz
 *
 * ─── Log Etiketleri ─────────────────────────────────────────────────────────
 * ATTACK_MATRIX : Saldırı tespiti / simülasyon logları
 */
object TamperHelper {

    private const val TAG = "TamperHelper"

    // ─── Tamper Modu Enum ───────────────────────────────────────────────────

    enum class TamperMode(val label: String, val prefKey: String) {
        NONE        ("🟢 Saldırı Yok",                        "NONE"),
        AMOUNT      ("💰 Tutar Manipülasyonu (5000 TL)",       "AMOUNT"),
        CARD_NUMBER ("💳 Kart No Manipülasyonu (son 4 hane)", "CARD_NUMBER"),
        TIMESTAMP   ("⏱ Zaman Damgası Manipülasyonu",         "TIMESTAMP"),
        ALL_FIELDS  ("☠️ Tüm Alanlar Manipüle",               "ALL_FIELDS");

        companion object {
            fun fromPrefKey(key: String): TamperMode =
                entries.firstOrNull { it.prefKey == key } ?: NONE
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  GÜVENSİZ MOD — JSON Manipülasyonu
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Güvensiz düz metin JSON payload'ını belirtilen saldırı moduna göre manipüle eder.
     *
     * Güvensiz modda HMAC yoktur → PSA bu değişikliği algılayamaz → İşlem KABUL edilir.
     * Bu durum "Data Tampering — No Protection" saldırısını gösterir.
     *
     * @param json  CPA'nın ürettiği orijinal JSON string
     * @param mode  Hangi alanların manipüle edileceği
     * @return Manipüle edilmiş JSON string
     */
    fun tamperInsecurePayload(json: String, mode: TamperMode): String {
        if (mode == TamperMode.NONE) return json

        return try {
            val obj = JSONObject(json)
            applyTampers(obj, mode)
            obj.put("tampered", true)
            val result = obj.toString()

            Log.w(TAG, "══════ TAMPER SIMÜLASYONU (GÜVENSİZ) ══════")
            Log.w(TAG, "  Mod       : $mode")
            Log.w(TAG, "  Orijinal  : $json")
            Log.w(TAG, "  Manipüle  : $result")
            Log.w(TAG, "═══════════════════════════════════════════")
            Log.w("ATTACK_MATRIX",
                "scenario=DATA_TAMPERING | mode=${mode.prefKey} | " +
                "mechanism=NONE | result=TAMPERED_ACCEPTED_NO_PROTECTION"
            )

            result
        } catch (e: Exception) {
            Log.e(TAG, "Tamper hatası (insecure)", e)
            json
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  GÜVENLİ MOD — Ciphertext Bozma
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Güvenli şifreli payload'ın ciphertext'ini bozar.
     *
     * Gerçek saldırıda: saldırgan ağ üzerinden geçen şifreli veriyi değiştirir.
     * Ancak HMAC'ı güncelleyemez → PSA HMAC doğrulamasında REDDEDER.
     *
     * Yalnızca ilk 2 karakter yer değiştirilir; bu küçük değişiklik bile
     * HMAC-SHA256 doğrulamasını tamamen bozar (avalanche effect).
     *
     * @param securePayload AES şifreli dış zarf JSON'u
     * @return Ciphertext bozulmuş JSON string
     */
    fun corruptSecurePayload(securePayload: String): String {
        return try {
            val json = JSONObject(securePayload)
            val ct   = json.getString("ciphertext")
            if (ct.length < 2) return securePayload

            // İlk 2 karakteri yer değiştir (basit ama HMAC'ı tamamen bozar)
            val corrupted = ct[1].toString() + ct[0].toString() + ct.substring(2)
            json.put("ciphertext", corrupted)

            Log.w(TAG, "══════ TAMPER SIMÜLASYONU (GÜVENLİ) ══════")
            Log.w(TAG, "  Orijinal ciphertext[0:2] : ${ct.take(2)}")
            Log.w(TAG, "  Bozulmuş ciphertext[0:2] : ${corrupted.take(2)}")
            Log.w(TAG, "  → PSA HMAC doğrulaması BAŞARISIZ olacak")
            Log.w(TAG, "═══════════════════════════════════════════")
            Log.w("ATTACK_MATRIX",
                "scenario=DATA_TAMPERING | mode=CIPHERTEXT_CORRUPT | " +
                "mechanism=HMAC-SHA256 | result=WILL_FAIL_HMAC_INTEGRITY_CHECK"
            )

            json.toString()
        } catch (e: Exception) {
            Log.e(TAG, "Tamper hatası (secure)", e)
            securePayload
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Veri Gönderme Fonksiyonları (HCE Mimarisine Uyarlanmış)
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Güvenli şifrelenmiş payload üretir.
     *
     * NOT: Bu uygulama HCE mimarisi kullandığından doğrudan NFC gönderimi
     * PaymentHceService.buildAndSendPayload() tarafından otomatik yapılır.
     * Bu fonksiyon payload'ı üretir; servis onu NFC APDU yanıtı olarak iletir.
     *
     * @param cardNumber Kart numarası
     * @param amount     Tutar
     * @return AES-256-CBC şifreli + HMAC-SHA256 imzalı JSON string
     */
    fun sendEncryptedData(cardNumber: String, amount: String): String {
        Log.d(TAG, "[sendEncryptedData] Şifreli payload üretiliyor...")
        val payload = CryptoHelper.buildSecurePayload(cardNumber, amount)
        Log.d(TAG, "[sendEncryptedData] Payload hazır (${payload.toByteArray().size} bytes) — HCE ile iletilecek")
        return payload
    }

    /**
     * Güvensiz düz metin payload üretir.
     *
     * @param cardNumber Kart numarası
     * @param amount     Tutar
     * @param tampered   Tamper flag
     * @return Şifrelenmemiş düz JSON string
     */
    fun sendInsecureData(cardNumber: String, amount: String, tampered: Boolean = false): String {
        Log.d(TAG, "[sendInsecureData] Güvensiz payload üretiliyor...")
        val payload = CryptoHelper.buildInsecurePayload(cardNumber, amount, tampered)
        Log.d(TAG, "[sendInsecureData] Payload hazır (${payload.toByteArray().size} bytes) — HCE ile iletilecek")
        return payload
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Özel Manipülasyon Fonksiyonları
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Genel manipülasyon: Seçilen moda göre JSON alanlarını değiştirir.
     */
    private fun applyTampers(obj: JSONObject, mode: TamperMode) {
        when (mode) {
            TamperMode.AMOUNT      -> tamperAmount(obj)
            TamperMode.CARD_NUMBER -> tamperCardNumber(obj)
            TamperMode.TIMESTAMP   -> tamperTimestamp(obj)
            TamperMode.ALL_FIELDS  -> {
                tamperCardNumber(obj)
                tamperAmount(obj)
                tamperTimestamp(obj)
            }
            TamperMode.NONE -> Unit
        }
    }

    /**
     * Kart numarasının son 4 hanesini "9999" ile değiştirir.
     * Gerçek saldırıda: saldırgan parayı kendi kartına yönlendirmek için
     * kart numarasının son hanelerini değiştirir.
     */
    private fun tamperCardNumber(obj: JSONObject) {
        val original = obj.optString("cardNumber", "")
        if (original.length >= 4) {
            val tampered = original.dropLast(4) + "9999"
            obj.put("cardNumber", tampered)
            Log.w(TAG, "[TAMPER] cardNumber: '$original' → '$tampered'")
        }
    }

    /**
     * Tutarı 5000.00 TL olarak değiştirir.
     * Gerçek saldırıda: saldırgan küçük bir tutarla başlar,
     * intercept ederek tutarı artırır veya azaltır.
     */
    private fun tamperAmount(obj: JSONObject) {
        val original = obj.optString("amount", "0")
        obj.put("amount", "5000.00")
        Log.w(TAG, "[TAMPER] amount: '$original' → '5000.00 TL'")
    }

    /**
     * Timestamp'i 2 saat öncesine çeker → PSA'nın 30 saniyelik penceresi dışına düşer.
     * Güvensiz modda: PSA timestamp kontrolü yapmaz → kabul edilir.
     * Güvenli modda: Timestamp kontrolü REDDEDER.
     */
    private fun tamperTimestamp(obj: JSONObject) {
        val original   = obj.optLong("timestamp", 0L)
        val manipulated = System.currentTimeMillis() - (2 * 60 * 60 * 1000L) // 2 saat önce
        obj.put("timestamp", manipulated)
        Log.w(TAG, "[TAMPER] timestamp: $original → $manipulated (-2 saat, window dışı)")
    }
}
