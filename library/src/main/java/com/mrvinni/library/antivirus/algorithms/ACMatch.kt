package com.mrvinni.library.antivirus.algorithms

import com.mrvinni.library.antivirus.Signature
import org.neosearch.stringsearcher.StringSearcher

class ACMatch : Algorithm {

    private var searcherName: StringSearcher<Signature>? = null
    private var searcherPackage: StringSearcher<Signature>? = null

    override fun updateSignatures(signatures: List<Signature>) {

        val builderName = StringSearcher.builderWithPayload<Signature>().ignoreOverlaps().stopOnHit()
        val builderPackage = StringSearcher.builderWithPayload<Signature>().ignoreOverlaps()

        for (signature in signatures) {
            if (signature.type == Signature.Type.PACKAGE)
                builderPackage.addSearchString(signature.virusSignature, signature)
            else if (signature.type == Signature.Type.NAME)
                builderName.addSearchString(signature.virusSignature, signature)
        }

        searcherName = builderName.build()
        searcherPackage = builderPackage.build()
    }

    override fun findStringSignatures(data: String, type: Signature.Type?, matchWhole: Boolean): List<Signature> {

        if (data.isEmpty())
            return listOf()

        if (searcherName == null && searcherPackage == null)
            return listOf()

        if (type == Signature.Type.NAME && searcherName == null)
            return listOf()

        if (type == Signature.Type.PACKAGE && searcherPackage == null)
            return listOf()

        if (matchWhole) {

            val match = when (type) {
                Signature.Type.NAME ->  searcherName!!.firstMatch(data)
                Signature.Type.PACKAGE -> searcherPackage!!.firstMatch(data)
                else -> searcherName!!.firstMatch(data) ?: searcherPackage!!.firstMatch(data)
            }

            return when {
                match == null -> listOf()
                match.size() != data.length -> listOf()
                else -> listOf<Signature>(match.payload)
            }

        } else {

            val list = arrayListOf<Signature>()

            val matches = when (type) {
                Signature.Type.NAME ->  searcherName!!.parseText(data)
                Signature.Type.PACKAGE -> searcherPackage!!.parseText(data)
                else -> searcherName!!.parseText(data) ?: searcherPackage!!.parseText(data)
            }

            matches.forEach { match -> list.add(match.payload) }

            return list
        }
    }

    override fun findBytesSignatures(data: ByteArray?, type: Signature.Type?, matchWhole: Boolean): List<Signature> {
        if (data == null)
            return listOf()
        return findStringSignatures(String(data), type, matchWhole)
    }
}