package com.nfc.wallet

import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * MainActivity — Rol Seçici
 *
 * NFC durumunu kontrol eder.
 * Kullanıcı CPA (müşteri) veya PSA (terminal) rolünü seçer.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var tvNfcStatus: TextView
    private lateinit var btnCpa:      Button
    private lateinit var btnPsa:      Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvNfcStatus = findViewById(R.id.tvNfcStatus)
        btnCpa      = findViewById(R.id.btnCpa)
        btnPsa      = findViewById(R.id.btnPsa)

        btnCpa.setOnClickListener {
            startActivity(Intent(this, CpaActivity::class.java))
        }
        btnPsa.setOnClickListener {
            startActivity(Intent(this, PsaActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        checkNfc()
    }

    private fun checkNfc() {
        val adapter = NfcAdapter.getDefaultAdapter(this)
        when {
            adapter == null -> {
                tvNfcStatus.text = "❌ Bu cihaz NFC desteklemiyor"
                btnCpa.isEnabled = false
                btnPsa.isEnabled = false
            }
            !adapter.isEnabled -> {
                tvNfcStatus.text = "⚠️ NFC kapalı — Ayarlardan açın"
                btnCpa.isEnabled = false
                btnPsa.isEnabled = false
            }
            else -> {
                tvNfcStatus.text = "✅ NFC Aktif"
                btnCpa.isEnabled = true
                btnPsa.isEnabled = true
            }
        }
    }
}
