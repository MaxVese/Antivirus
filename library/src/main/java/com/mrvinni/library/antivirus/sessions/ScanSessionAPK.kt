package com.mrvinni.library.antivirus.sessions

import com.mrvinni.library.antivirus.ApkFile
import com.mrvinni.library.antivirus.Signature
import com.mrvinni.library.antivirus.algorithms.Algorithm
import com.mrvinni.library.antivirus.AppInf

class ScanSessionAPK(
    private val app: AppInf,
    private val algorithm: Algorithm,
    private val mode: Mode
) : ScanSession() {

    enum class Mode {
        METADATA,
        FULL
    }

    companion object {
        private val RESOURCES_EXT = arrayOf("xml", "json", "txt", "html")
        private val RESOURCES_PATHS = arrayOf("res/raw/", "res/xml/", "assets/")
    }

    override fun performScan(): ScanResult {

        // Default scan for name and package
        signatures.addAll(algorithm.findStringSignatures(app.appName, Signature.Type.NAME))
        signatures.addAll(algorithm.findStringSignatures(app.appPackage,
            Signature.Type.PACKAGE, matchWhole = true))

        // Found some obvious shit, return early
        if (signatures.isNotEmpty())
            return ScanResult(signatures, ScanResult.TrustFactor.FOUND_TRUSTED)

        app.openApkFile().use { apk ->

            // Scan manifest
            scanManifest(apk)

            // If FULL - Scan DEX classes and APK resources
            if (mode == Mode.FULL) {
                scanDexClasses(apk)
                scanResources(apk)
            }
        }

        //Log.d("MYTAG", "App ${app.appName} Signatures finally: ${signatures.size}")

        return ScanResult(signatures, calculateTrustFactor())
    }

    private fun scanManifest(apk: ApkFile) {

        val manifest = apk.manifestXml

        // Extract packages from manifest:
        val regexPackage = Regex("package=\"(.*?)\"")
        val regexName = Regex(":name=\"(.*?)\"")

        val names = regexName.findAll(manifest)
        val packages = regexPackage.findAll(manifest)

        for (match in names)
            signatures.addAll(algorithm.findStringSignatures(match.destructured.component1(), matchWhole = true))

        for (match in packages)
            signatures.addAll(algorithm.findStringSignatures(match.destructured.component1(), matchWhole = true))

        //Log.d("MYTAG", "App ${app.appName} Signatures in manifest: ${signatures.size}")
    }

    private fun scanResources(apk: ApkFile) {
        apk.iterateResources(
            includePaths = RESOURCES_PATHS,
            includeExtensions = RESOURCES_EXT,
            includeResourceTable = true)
        { name, content ->
            signatures.addAll(algorithm.findStringSignatures(content))
        }

        //Log.d("MYTAG", "App ${app.appName} Signatures in resources: ${signatures.size}")
    }

    private fun scanDexClasses(apk: ApkFile){
        apk.dexClasses?.forEach { dexClass ->
            val classPackage = dexClass.packageName
            signatures.addAll(algorithm.findStringSignatures(classPackage,
                Signature.Type.PACKAGE, true))
        }
        //Log.d("MYTAG", "App ${app.appName} Signatures in Dex: ${signatures.size}")
    }

}