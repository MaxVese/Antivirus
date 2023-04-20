package com.mrvinni.library.antivirus

class Signature(
    val type: Type,
    val virusName: String,
    val virusSignature: String
) {

    enum class Type {
        NAME,
        PACKAGE
    }

    override fun toString(): String {
        return virusName
    }
}