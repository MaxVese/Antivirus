package com.mrvinni.library.antivirus

import android.content.Context
import com.mrvinni.library.antivirus.algorithms.ACMatch
import com.mrvinni.library.antivirus.sessions.ScanResult
import com.mrvinni.library.antivirus.sessions.ScanSessionAPK
import com.mrvinni.library.antivirus.sessions.ScanSessionFile
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import kotlin.collections.ArrayList

class Antivirus {

    var scanModeFiles = ScanSessionFile.Mode.SIMPLE
    var scanModeApps = ScanSessionAPK.Mode.METADATA

    private var algorithm = ACMatch()
    private val signatures = ArrayList<Signature>()

    fun loadSignatures(json: JSONObject) {
        signatures.clear()
        try {
            val names = json.getJSONArray("names")
            val packages = json.getJSONArray("packages")

            for (i in 0 until names.length()) {
                val signature = Signature(
                    Signature.Type.NAME,
                    names.getString(i),
                    names.getString(i)
                )
                signatures.add(signature)
            }

            for (i in 0 until packages.length()) {
                val signature = Signature(
                    Signature.Type.PACKAGE,
                    packages.getString(i),
                    packages.getString(i)
                )
                signatures.add(signature)
            }

        } catch (ex: IOException) {
            /* ... */
        } catch (ex: JSONException) {
            /* ... */
        }

        algorithm.updateSignatures(signatures)
    }

    fun scanApp(app: AppInf): ScanResult {
        val session = ScanSessionAPK(
            app = app,
            algorithm = algorithm,
            mode = scanModeApps
        )
        return session.performScan()
    }

    fun scanFile(file: File): ScanResult {
        val session = ScanSessionFile(
            file = file,
            algorithm = algorithm,
            mode = scanModeFiles
        )
        return session.performScan()
    }



}