package com.nfc.wallet

import android.util.Log

/**
 * KeyManager — Merkezi Anahtar Yönetimi
 *
 * ─── GÜVENLİK UYARISI ───────────────────────────────────────────────────────
 * Bu dosyadaki anahtarlar **akademik demo** amaçlı hardcoded olarak tanımlanmıştır.
 * ÜRETİM ORTAMINDA kesinlikle kullanılmamalıdır!
 *
 * Üretim için önerilen yaklaşımlar:
 *   1. Android Keystore System (simetrik anahtar HW güvenli alanda saklanır)
 *   2. EncryptedSharedPreferences (Tink kütüphanesi ile)
 *   3. Uzak anahtar yönetim sunucusundan (KMS) HTTPS ile alınır
 *   4. ECDH anahtar değişimi → her oturum için türetilmiş anahtar
 *
 * ─── Demo Proje Kısıtlaması ──────────────────────────────────────────────────
 * CPA ve PSA aynı uygulamada çalıştığından ve NFC üzerinden paylaşım yapıldığından
 * pre-shared key (PSK) yaklaşımı kullanılmaktadır.
 * Gerçek sistemde her ödeme terminali için ayrı anahtar çifti olmalıdır.
 *
 * ─── Keystore Entegrasyonu (Üretim Örneği) ───────────────────────────────────
 * ```kotlin
 * val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
 * val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
 * keyGenerator.init(
 *     KeyGenParameterSpec.Builder("NfcWalletKey",
 *         KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
 *         .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
 *         .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
 *         .setRandomizedEncryptionRequired(true)
 *         .setUserAuthenticationRequired(true)  // Biyometrik doğrulama
 *         .build()
 * )
 * keyGenerator.generateKey()
 * ```
 */
object KeyManager {

    private const val TAG = "KeyManager"

    // ─── Pre-Shared Keys (Demo) ───────────────────────────────────────────────
    // Her ikisi de tam 32 byte — AES-256 ve HMAC-SHA256 için
    // ÜRETİMDE: Bu değerler kaynak kodda yer ALMAMALI
    private const val AES_KEY_RAW  = "NfcSecureAesKey!NfcSecureAesKey!" // 32 byte
    private const val HMAC_KEY_RAW = "NfcSecureHmacKey2024SecureHmac!!" // 32 byte

    /**
     * AES-256-CBC için anahtar byte dizisi.
     * Üretimde: Android Keystore'dan SecretKey nesnesi döndürülür.
     */
    fun getAesKeyBytes(): ByteArray {
        Log.w(TAG, "[KEY_ACCESS] AES anahtarı kullanıldı — Demo mod (hardcoded)")
        return AES_KEY_RAW.toByteArray(Charsets.UTF_8)
    }

    /**
     * HMAC-SHA256 için anahtar byte dizisi.
     * Üretimde: Keystore'dan veya güvenli bir KMS'den alınır.
     */
    fun getHmacKeyBytes(): ByteArray {
        Log.w(TAG, "[KEY_ACCESS] HMAC anahtarı kullanıldı — Demo mod (hardcoded)")
        return HMAC_KEY_RAW.toByteArray(Charsets.UTF_8)
    }

    /**
     * Anahtar uzunluklarını doğrular.
     * Uygulama başlangıcında çağrılarak konfigürasyon hatasını erken yakalar.
     *
     * @throws IllegalStateException Anahtar boyutu hatalıysa
     */
    fun validateKeys() {
        val aesLen  = AES_KEY_RAW.toByteArray(Charsets.UTF_8).size
        val hmacLen = HMAC_KEY_RAW.toByteArray(Charsets.UTF_8).size

        check(aesLen == 32)  { "AES anahtarı 32 byte olmalı! Mevcut: $aesLen" }
        check(hmacLen == 32) { "HMAC anahtarı 32 byte olmalı! Mevcut: $hmacLen" }

        Log.i(TAG, "✅ Anahtar doğrulama geçti — AES:${aesLen}B HMAC:${hmacLen}B")
    }
}
