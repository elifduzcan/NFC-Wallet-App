# NFC-Wallet-App
Android-based NFC payment wallet simulation using Host Card Emulation (HCE), secure communication, encryption, HMAC verification, and tamper attack detection.

# NFC Wallet App

An Android NFC payment wallet prototype developed with Kotlin.

The application simulates contactless payment transactions using Host Card Emulation (HCE) and demonstrates secure communication mechanisms such as encryption, HMAC verification, and tamper detection.

## Features

- NFC-based payment simulation
- Host Card Emulation (HCE)
- CPA (Customer Payment Application) mode
- PSA (Payment Service Application / Terminal) mode
- Secure and insecure communication modes
- Transaction integrity verification with HMAC
- Tamper attack simulation
- Local transaction storage
- Performance monitoring

## Technologies

- Kotlin
- Android SDK
- NFC / HCE
- Room Database
- SharedPreferences
- AES Encryption
- HMAC Verification

## Project Structure

- `MainActivity` – Role selection screen
- `CpaActivity` – Customer-side payment application
- `PsaActivity` – Terminal-side payment application
- `PaymentHceService` – HCE card emulation service
- `CryptoHelper` – Encryption and integrity operations
- `TamperHelper` – Tamper attack simulation
- `AppDatabase` – Local transaction storage

## Requirements

- Android device with NFC support
- Android 8.0 or later
- NFC enabled on the device

## Purpose

This project was developed as an educational prototype to demonstrate secure NFC payment communication and the effects of data tampering on transaction integrity.
