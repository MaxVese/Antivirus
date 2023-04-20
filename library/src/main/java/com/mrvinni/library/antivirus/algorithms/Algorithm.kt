package com.mrvinni.library.antivirus.algorithms

import com.mrvinni.library.antivirus.Signature

interface Algorithm {

    fun updateSignatures(signatures: List<Signature>)

    fun findStringSignatures(data: String, type: Signature.Type? = null, matchWhole: Boolean = false): List<Signature>
    fun findBytesSignatures(data: ByteArray?, type: Signature.Type? = null, matchWhole: Boolean = false): List<Signature>
}