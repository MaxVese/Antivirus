package com.mrvinni.library.antivirus.sessions

import android.net.Uri
import android.webkit.MimeTypeMap
import com.mrvinni.library.antivirus.algorithms.Algorithm
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.nio.file.Files
import java.util.*

class ScanSessionFile(
    private val algorithm: Algorithm,
    private val file: File,
    private val mode: Mode
) : ScanSession() {

    enum class Mode {
        SIMPLE,
        PRECISE,
        AT_ONCE
    }

    companion object {
        private val EXTENSIONS_SKIP = arrayOf("jpg", "png", "mov", "mp3", "wav", "mp4")
        private const val BUFFER_SIZE = 12582912
        private const val BUFFER_OFFSET = BUFFER_SIZE / 2
    }

    private val buffer = ByteArray(BUFFER_SIZE)

    override fun performScan(): ScanResult {
        val uri = Uri.fromFile(file).toString()
        val extension = MimeTypeMap.getFileExtensionFromUrl(uri).lowercase(Locale.getDefault())
        if (EXTENSIONS_SKIP.contains(extension))
            return ScanResult(signatures, ScanResult.TrustFactor.FOUND_NONE)

        try {
            when (mode) {
                Mode.SIMPLE -> scanFileSimple(file)
                Mode.PRECISE -> scanFilePrecise(file)
                Mode.AT_ONCE -> scanFileAtOnce(file)
            }
        } catch (e: IOException) {
            /* ignore */
        }

        return ScanResult(signatures, calculateTrustFactor())

    }

    private fun scanFileSimple(file: File) {
        Arrays.fill(buffer, 0.toByte())
        FileInputStream(file).use { stream ->
            while (stream.read(buffer) != -1) {
                signatures.addAll(algorithm.findBytesSignatures(buffer))
            }
        }
    }

    private fun scanFilePrecise(file: File) {
        Arrays.fill(buffer, 0.toByte())
        FileInputStream(file).use { stream ->
            val bytesRead = stream.read(buffer,
                BUFFER_OFFSET, BUFFER_SIZE - BUFFER_OFFSET
            )
            while (bytesRead != -1) {
                signatures.addAll(algorithm.findBytesSignatures(buffer))
                System.arraycopy(buffer, BUFFER_OFFSET, buffer, 0, bytesRead)
            }
        }
    }

    private fun scanFileAtOnce(file: File) {
        val fileBytes = Files.readAllBytes(file.toPath())
        signatures.addAll(algorithm.findBytesSignatures(fileBytes))
    }

}