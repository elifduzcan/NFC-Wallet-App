package com.nfc.wallet

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Payment — Room Entity
 *
 * Her başarılı veya başarısız işlem bu tabloya kaydedilir.
 *
 * @param id         Otomatik artan primary key
 * @param cardNumber Kart numarası (güvenli modda şifreli tutulur)
 * @param amount     Tutar
 * @param currency   Para birimi (TL)
 * @param token      UUID token — replay tespiti için indekslenir
 * @param timestamp  Unix timestamp (ms)
 * @param isSecure   Güvenli mod ile mi işlendi
 * @param result     "ACCEPTED" | "REJECTED" | "REPLAY_BLOCKED" | "TAMPERED"
 * @param note       Ek açıklama (hata mesajı vs.)
 */
@Entity(tableName = "payment_table")
data class Payment(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val cardNumber: String,
    val amount:     String,
    val currency:   String   = "TL",
    val token:      String?  = null,     // Güvenli modda UUID, güvensiz modda null
    val timestamp:  Long,
    val isSecure:   Boolean  = false,
    val result:     String   = "ACCEPTED",
    val note:       String   = ""
)
