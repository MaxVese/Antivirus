package com.mrvinni.library.antivirus.algorithms

import com.mrvinni.library.antivirus.Signature
import java.nio.charset.StandardCharsets

/**
 * Knuth-Morris-Pratt Algorithm for Pattern Matching
 */
class KMPMatch : Algorithm {

    private var signatures: List<Signature>? = null

    override fun updateSignatures(signatures: List<Signature>) {
        this.signatures = signatures
    }

    override fun findStringSignatures(data: String, type: Signature.Type?, matchWhole: Boolean): List<Signature> {
        if (data.isEmpty())
            return listOf()
        return findBytesSignatures(data.toByteArray(StandardCharsets.UTF_8), type, matchWhole)
    }

    override fun findBytesSignatures(data: ByteArray?, type: Signature.Type?, matchWhole: Boolean): List<Signature> {

        if (data == null || signatures == null || signatures!!.isEmpty())
            return listOf()

        val list = arrayListOf<Signature>()

        signatures!!.asSequence()
            .filter { if (type != null) it.type == type else true }
            .forEach { signature ->
                val virusBytes = signature.virusSignature.toByteArray(StandardCharsets.UTF_8)
                if (indexOf(data, virusBytes) != -1)
                    list.add(signature)
            }
        return list
    }

    companion object {

        /**
         * Finds the first occurrence of the pattern in the text.
         */
        private fun indexOf(data: ByteArray, pattern: ByteArray): Int {
            if (data.isEmpty()) return -1
            val failure = computeFailure(pattern)
            var j = 0
            for (i in data.indices) {
                while (j > 0 && pattern[j] != data[i]) {
                    j = failure[j - 1]
                }
                if (pattern[j] == data[i]) {
                    j++
                }
                if (j == pattern.size) {
                    return i - pattern.size + 1
                }
            }
            return -1
        }

        /**
         * Computes the failure function using a boot-strapping process,
         * where the pattern is matched against itself.
         */
        private fun computeFailure(pattern: ByteArray): IntArray {
            val failure = IntArray(pattern.size)
            var j = 0
            for (i in 1 until pattern.size) {
                while (j > 0 && pattern[j] != pattern[i]) {
                    j = failure[j - 1]
                }
                if (pattern[j] == pattern[i]) {
                    j++
                }
                failure[i] = j
            }
            return failure
        }
    }
}