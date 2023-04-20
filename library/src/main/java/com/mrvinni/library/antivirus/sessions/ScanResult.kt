package com.mrvinni.library.antivirus.sessions

import com.mrvinni.library.antivirus.Signature

class ScanResult(
    val signatures: List<Signature>,
    val trustFactor: TrustFactor = TrustFactor.FOUND_NONE
) {

    enum class TrustFactor {
        FOUND_NONE,
        FOUND_UNTRUSTED,
        FOUND_TRUSTED
    }

}