package com.nfc.wallet

import android.util.Log

/**
 * PerformanceTracker — Merkezi Performans Ölçüm ve İstatistik Sistemi
 *
 * Tüm kritik işlem adımlarının sürelerini biriktirir ve
 * istatistiksel analiz (min / max / ortalama / std sapma) sağlar.
 *
 * ─── Ölçüm Noktaları ────────────────────────────────────────────────────────
 * CPA Tarafı:
 *   CPA_DATA_PREP        : JSON oluşturma
 *   CPA_AES_ENCRYPT      : AES-256-CBC şifreleme
 *   CPA_HMAC_COMPUTE     : HMAC-SHA256 hesaplama
 *   CPA_TOTAL_BUILD      : Toplam payload üretim süresi
 *
 * NFC İletim:
 *   NFC_SELECT           : SELECT AID komutu iletim süresi
 *   NFC_GET_DATA         : GET DATA komutu iletim süresi
 *   NFC_TOTAL            : Toplam NFC iletim süresi
 *
 * PSA Tarafı:
 *   PSA_HMAC_VERIFY      : HMAC doğrulama süresi
 *   PSA_AES_DECRYPT      : AES-256-CBC şifre çözme süresi
 *   PSA_TOKEN_CHECK      : Token + timestamp doğrulama süresi
 *   PSA_TOTAL_VERIFY     : Toplam PSA doğrulama süresi
 *
 * Uçtan Uca:
 *   E2E_TOTAL            : NFC tap → ACCEPTED/REJECTED arası toplam süre
 *   E2E_REAL_CPA         : CPA t0'dan PSA sonuna kadar gerçek E2E
 *
 * ─── Log Etiketleri ─────────────────────────────────────────────────────────
 * PERF_RECORD  : Her bireysel ölçüm kaydı
 * PERF_REPORT  : İstatistiksel özet raporu (rapor butonuyla tetiklenir)
 */
object PerformanceTracker {

    private const val TAG        = "PERF_RECORD"
    private const val REPORT_TAG = "PERF_REPORT"

    /** Her etiket için birden fazla ölçüm biriktirilir */
    private val records = mutableMapOf<String, MutableList<Double>>()

    /** Aktif başlatılmış timer'lar */
    private val activeTimers = mutableMapOf<String, Long>()

    /** Toplam kayıt sayısı (her mod için ayrı tutulabilir) */
    var transactionCount: Int = 0
        private set

    // ── Timer API ─────────────────────────────────────────────────────────────

    /**
     * Zamanlayıcı başlatır.
     * @param label Ölçüm etiketi (örn: "CPA_AES_ENCRYPT")
     */
    fun start(label: String) {
        activeTimers[label] = System.nanoTime()
    }

    /**
     * Zamanlayıcıyı durdurur ve süreyi kaydeder.
     * @return Geçen süre (ms), başlatılmamışsa -1.0
     */
    fun stop(label: String): Double {
        val startNs = activeTimers.remove(label) ?: return -1.0
        val durationMs = (System.nanoTime() - startNs) / 1_000_000.0
        record(label, durationMs)
        return durationMs
    }

    /**
     * Hazır hesaplanmış süreyi doğrudan kaydeder.
     * Mevcut `(t1 - t0) / 1_000_000.0` hesaplarıyla uyumludur.
     *
     * @param label      Ölçüm etiketi
     * @param durationMs Geçen süre (milisaniye cinsinden)
     * @param mode       "SECURE" | "INSECURE" | "" — log için etiket
     */
    fun record(label: String, durationMs: Double, mode: String = "") {
        records.getOrPut(label) { mutableListOf() }.add(durationMs)
        val modeStr = if (mode.isNotBlank()) "[$mode] " else ""
        Log.i(TAG, "$modeStr[$label] ${"%.4f".format(durationMs)} ms")
    }

    // ── İstatistik API ────────────────────────────────────────────────────────

    /**
     * Belirli bir etiket için istatistikleri hesaplar.
     *
     * @return TimingStats nesnesi, kayıt yoksa null
     */
    fun getStats(label: String): TimingStats? {
        val values = records[label]?.takeIf { it.isNotEmpty() } ?: return null
        val sorted = values.sorted()
        val avg    = values.average()
        val variance = values.map { (it - avg) * (it - avg) }.average()
        return TimingStats(
            label  = label,
            count  = values.size,
            min    = sorted.first(),
            max    = sorted.last(),
            avg    = avg,
            median = if (sorted.size % 2 == 0)
                (sorted[sorted.size / 2 - 1] + sorted[sorted.size / 2]) / 2.0
            else
                sorted[sorted.size / 2].toDouble(),
            stdDev = Math.sqrt(variance),
            last   = values.last()
        )
    }

    /**
     * Tüm ölçüm etiketlerinin listesi.
     */
    fun getAllLabels(): Set<String> = records.keys.toSet()

    // ── Raporlama ─────────────────────────────────────────────────────────────

    /**
     * Logcat'e tam istatistik raporu yazar.
     * Her N işlemden sonra veya rapor butonuna basılınca çağrılır.
     *
     * Akademik tablo için: Logcat → PERF_REPORT filtresi.
     */
    fun logReport(mode: String = "") {
        val modeLabel = if (mode.isNotBlank()) " [$mode]" else ""
        Log.i(REPORT_TAG, "╔══════════════════════════════════════════════════════════╗")
        Log.i(REPORT_TAG, "║  PERFORMANS RAPORU$modeLabel  |  İşlem Sayısı: $transactionCount")
        Log.i(REPORT_TAG, "╠══════════════════════════════════════════════════════════╣")
        Log.i(REPORT_TAG, "  %-20s %5s %8s %8s %8s %8s %8s".format(
            "ETIKET", "N", "MIN(ms)", "AVG(ms)", "MEDIAN", "MAX(ms)", "STDDEV"
        ))
        Log.i(REPORT_TAG, "  " + "─".repeat(72))

        val order = listOf(
            "CPA_DATA_PREP", "CPA_AES_ENCRYPT", "CPA_HMAC_COMPUTE", "CPA_TOTAL_BUILD",
            "NFC_SELECT", "NFC_GET_DATA", "NFC_TOTAL",
            "PSA_HMAC_VERIFY", "PSA_AES_DECRYPT", "PSA_TOKEN_CHECK", "PSA_TOTAL_VERIFY",
            "E2E_TOTAL", "E2E_REAL_CPA"
        )

        // Önce sıralı liste, sonra varsa kalanlar
        val allLabels = order.filter { it in records } + (records.keys - order.toSet())

        for (label in allLabels) {
            val s = getStats(label) ?: continue
            Log.i(REPORT_TAG, "  %-20s %5d %8s %8s %8s %8s %8s".format(
                label.take(20),
                s.count,
                "%.3f".format(s.min),
                "%.3f".format(s.avg),
                "%.3f".format(s.median),
                "%.3f".format(s.max),
                "%.3f".format(s.stdDev)
            ))
        }
        Log.i(REPORT_TAG, "╚══════════════════════════════════════════════════════════╝")
    }

    /**
     * Güvenli ve güvensiz mod karşılaştırma raporu.
     * Akademik bölüm: "Güvenli vs Güvensiz Performans Karşılaştırması"
     */
    fun logComparisonReport(secureStats: Map<String, TimingStats>, insecureStats: Map<String, TimingStats>) {
        Log.i(REPORT_TAG, "╔══════════════════════════════════════════════════════════╗")
        Log.i(REPORT_TAG, "║  KARŞILAŞTIRMA: GÜVENLİ vs GÜVENSİZ")
        Log.i(REPORT_TAG, "╠══════════════════════════════════════════════════════════╣")
        Log.i(REPORT_TAG, "  %-20s %10s %10s %10s".format("ETIKET", "GÜVENSİZ", "GÜVENLİ", "FARK"))
        Log.i(REPORT_TAG, "  " + "─".repeat(52))

        val compareLabels = listOf("E2E_TOTAL", "PSA_TOTAL_VERIFY", "CPA_TOTAL_BUILD", "NFC_TOTAL")
        for (label in compareLabels) {
            val ins = insecureStats[label]?.avg ?: continue
            val sec = secureStats[label]?.avg   ?: continue
            val diff = sec - ins
            Log.i(REPORT_TAG, "  %-20s %10s %10s %+10s".format(
                label.take(20),
                "${"%.2f".format(ins)}ms",
                "${"%.2f".format(sec)}ms",
                "${"%.2f".format(diff)}ms"
            ))
        }
        Log.i(REPORT_TAG, "╚══════════════════════════════════════════════════════════╝")
    }

    // ── Kontrol ───────────────────────────────────────────────────────────────

    /** İşlem sayacını artırır */
    fun incrementTransaction() { transactionCount++ }

    /** Tüm kayıtları sıfırlar */
    fun clear() {
        records.clear()
        activeTimers.clear()
        transactionCount = 0
        Log.d(REPORT_TAG, "Performans verileri sıfırlandı")
    }

    /** Belirli bir etiketin kayıtlarını sıfırlar */
    fun clearLabel(label: String) {
        records.remove(label)
    }
}

// ── Veri Sınıfı ───────────────────────────────────────────────────────────────

/**
 * TimingStats — Tek bir ölçüm etiketinin istatistikleri.
 *
 * Akademik rapor tablosu için kullanılır.
 */
data class TimingStats(
    val label:  String,
    val count:  Int,
    val min:    Double,   // ms
    val max:    Double,   // ms
    val avg:    Double,   // ms — aritmetik ortalama
    val median: Double,   // ms — medyan
    val stdDev: Double,   // ms — standart sapma
    val last:   Double    // ms — son ölçüm
) {
    fun toLogString() =
        "[${label}] N=$count | min=${"%.3f".format(min)}ms | " +
        "avg=${"%.3f".format(avg)}ms | median=${"%.3f".format(median)}ms | " +
        "max=${"%.3f".format(max)}ms | σ=${"%.3f".format(stdDev)}ms"
}
