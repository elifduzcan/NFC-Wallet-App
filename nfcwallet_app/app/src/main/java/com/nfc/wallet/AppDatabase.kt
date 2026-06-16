package com.nfc.wallet

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

/**
 * AppDatabase — Room Veritabanı Singleton
 *
 * Version 1: payment_table oluşturuldu.
 *
 * Kullanım:
 *   val db  = AppDatabase.getInstance(context)
 *   val dao = db.paymentDao()
 */
@Database(entities = [Payment::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {

    abstract fun paymentDao(): PaymentDao

    companion object {
        private const val DB_NAME = "nfc_wallet_db"

        @Volatile
        private var INSTANCE: AppDatabase? = null

        /**
         * Thread-safe singleton.
         * İlk çağrıda veritabanını oluşturur, sonrakilerde aynı instance'ı döndürür.
         */
        fun getInstance(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    DB_NAME
                )
                    .fallbackToDestructiveMigration() // Versiyon değişiminde tabloyu sıfırla
                    .build()
                    .also { INSTANCE = it }
            }
        }
    }
}
