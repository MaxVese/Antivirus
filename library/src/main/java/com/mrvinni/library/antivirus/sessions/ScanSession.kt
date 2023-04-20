package com.mrvinni.library.antivirus.sessions

import com.mrvinni.library.antivirus.Signature
import com.mrvinni.library.antivirus.sessions.ScanResult

abstract class ScanSession {

    protected val signatures = arrayListOf<Signature>()

    protected fun calculateTrustFactor(): ScanResult.TrustFactor {
        return when (signatures.size) {
            0 -> ScanResult.TrustFactor.FOUND_NONE
            in 1..10 -> ScanResult.TrustFactor.FOUND_UNTRUSTED
            else -> ScanResult.TrustFactor.FOUND_TRUSTED
        }
    }

    abstract fun performScan(): ScanResult
}