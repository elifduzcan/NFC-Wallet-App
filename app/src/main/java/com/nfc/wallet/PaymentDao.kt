package com.nfc.wallet

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

/**
 * PaymentDao — Gelişmiş Veri Erişim Arayüzü
 *
 * ─── Replay Attack Tespiti ────────────────────────────────────────────────────
 * findByToken() → Aynı token daha önce kullanıldıysa REJECTED döner.
 * Bu kontrol CryptoHelper in-memory check'e EK olarak DB seviyesinde yapılır.
 * Böylece uygulama kapanıp açılsa bile replay koruması kalıcıdır.
 *
 * ─── Veri Doğrulama / Audit ───────────────────────────────────────────────────
 * getByResult()      → Belirli sonuçtaki işlemleri filtreler
 * getTamperedCount() → Tamper tespit sayısını döndürür
 * getStats()         → Tüm istatistikleri bir sorguda alır
 *
 * ─── Performans ───────────────────────────────────────────────────────────────
 * token kolonu için index eklenirse findByToken() O(1) olur.
 * (Bkz. Payment entity'deki @Index notasyonu)
 */
@Dao
interface PaymentDao {

    // ── Temel İşlemler ────────────────────────────────────────────────────────

    /** Yeni ödeme kaydı ekler */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(payment: Payment)

    // ── Replay Attack Tespiti ─────────────────────────────────────────────────

    /**
     * Belirli bir token'ın daha önce kullanılıp kullanılmadığını DB seviyesinde kontrol eder.
     *
     * Kullanım örneği (PsaActivity):
     * ```kotlin
     * val existing = paymentDao.findByToken(receivedToken)
     * if (existing != null) {
     *     showRejected("❌ DB Replay: Token daha önce kullanılmış!")
     * }
     * ```
     *
     * @param token UUID token string
     * @return Eşleşen Payment kaydı, bulunamazsa null
     */
    @Query("SELECT * FROM payment_table WHERE token = :token LIMIT 1")
    suspend fun findByToken(token: String): Payment?

    /**
     * Tüm kayıtlı token'ları döndürür.
     * Uygulama başlangıcında in-memory usedTokens set'ini yükler.
     */
    @Query("SELECT token FROM payment_table WHERE token IS NOT NULL")
    suspend fun getAllTokens(): List<String?>

    // ── Sorgulama ─────────────────────────────────────────────────────────────

    /** Tüm ödemeleri en yeniden eskiye listeler */
    @Query("SELECT * FROM payment_table ORDER BY timestamp DESC")
    suspend fun getAllPayments(): List<Payment>

    /** En son kaydedilen ödemeyi döndürür */
    @Query("SELECT * FROM payment_table ORDER BY timestamp DESC LIMIT 1")
    suspend fun getLastPayment(): Payment?

    /**
     * Belirli bir sonuca göre ödemeleri filtreler.
     *
     * @param result "ACCEPTED" | "REJECTED" | "REPLAY_BLOCKED" | "TAMPERED"
     */
    @Query("SELECT * FROM payment_table WHERE result = :result ORDER BY timestamp DESC")
    suspend fun getByResult(result: String): List<Payment>

    /** Güvenli modda yapılan ödemeleri döndürür */
    @Query("SELECT * FROM payment_table WHERE isSecure = 1 ORDER BY timestamp DESC")
    suspend fun getSecurePayments(): List<Payment>

    /** Güvensiz modda yapılan ödemeleri döndürür */
    @Query("SELECT * FROM payment_table WHERE isSecure = 0 ORDER BY timestamp DESC")
    suspend fun getInsecurePayments(): List<Payment>

    // ── İstatistik Sorguları ──────────────────────────────────────────────────

    /** Toplam kayıt sayısı */
    @Query("SELECT COUNT(*) FROM payment_table")
    suspend fun count(): Int

    /** Kabul edilen işlem sayısı */
    @Query("SELECT COUNT(*) FROM payment_table WHERE result = 'ACCEPTED'")
    suspend fun countAccepted(): Int

    /** Reddedilen işlem sayısı (tamper + replay dahil) */
    @Query("SELECT COUNT(*) FROM payment_table WHERE result != 'ACCEPTED'")
    suspend fun countRejected(): Int

    /**
     * Replay Attack ile bloke edilen işlem sayısı.
     * Akademik tablo: Replay Attack Tespiti sütunu için.
     */
    @Query("SELECT COUNT(*) FROM payment_table WHERE result = 'REPLAY_BLOCKED'")
    suspend fun countReplayBlocked(): Int

    /**
     * Tamper tespiti ile reddedilen işlem sayısı.
     * Akademik tablo: Data Tampering Tespiti sütunu için.
     */
    @Query("SELECT COUNT(*) FROM payment_table WHERE result = 'REJECTED'")
    suspend fun getTamperedCount(): Int

    /**
     * Güvenli mod istatistikleri — tek sorguda.
     * Performans tablosu ve radar grafiği için kullanılır.
     *
     * @return PaymentStats data nesnesi
     */
    @Query("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN result = 'ACCEPTED'       THEN 1 ELSE 0 END) as accepted,
            SUM(CASE WHEN result = 'REJECTED'        THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN result = 'REPLAY_BLOCKED'  THEN 1 ELSE 0 END) as replayBlocked,
            SUM(CASE WHEN isSecure = 1               THEN 1 ELSE 0 END) as secureCount,
            SUM(CASE WHEN isSecure = 0               THEN 1 ELSE 0 END) as insecureCount
        FROM payment_table
    """)
    suspend fun getStats(): PaymentStats

    // ── Yönetim ───────────────────────────────────────────────────────────────

    /** Tüm ödeme geçmişini siler (mod sıfırlama / test için) */
    @Query("DELETE FROM payment_table")
    suspend fun clearAll()
}

/**
 * PaymentStats — İstatistik Sorgu Sonucu
 *
 * Room @Query ile populate edilir — ek kod gerekmez.
 * Akademik tablolar için Logcat'e yazılır.
 */
data class PaymentStats(
    val total:         Int,
    val accepted:      Int,
    val rejected:      Int,
    val replayBlocked: Int,
    val secureCount:   Int,
    val insecureCount: Int
) {
    fun toLogString() =
        "TOTAL=$total | ACCEPTED=$accepted | REJECTED=$rejected | " +
        "REPLAY_BLOCKED=$replayBlocked | SECURE=$secureCount | INSECURE=$insecureCount"
}
