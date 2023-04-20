package com.mrvinni.library.antivirus

import net.dongliu.apk.parser.AbstractApkFile
import net.dongliu.apk.parser.bean.ApkSignStatus
import net.dongliu.apk.parser.struct.AndroidConstants
import net.dongliu.apk.parser.utils.Inputs
import java.io.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.*
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import kotlin.collections.ArrayList

class ApkFile(
    private val file: File
) : AbstractApkFile(), Closeable {
    private val zipFile: ZipFile = ZipFile(file)
    private var fileChannel: FileChannel? = null

    constructor(filePath: String) : this(File(filePath))

    fun iterateResources(
        includePaths: Array<String>? = arrayOf("res/"),
        includeExtensions: Array<String>? = null,
        includeResourceTable: Boolean = false,
        run: (name: String, content: String) -> Unit) {

        zipFile.entries().asSequence()
            .filter { entry -> includePaths?.any { entry.name.startsWith(it) } ?: true}
            .filter { entry -> includeExtensions?.any { entry.name.endsWith(it) } ?: true }
            .forEach { entry ->
                val content = getResourceContent(entry.name)
                run(entry.name, content)
            }

        if (includeResourceTable) {
            val entry = zipFile.getEntry(AndroidConstants.RESOURCE_FILE)
            val content = getEntryContent(entry)
            run(entry.name, content)
        }
    }

    private fun getResourceContent(name: String): String {
        return try {
            if (name.endsWith("xml")) {
                transBinaryXml(name)
            } else {
                getEntryContent(zipFile.getEntry(name))
            }
        } catch (ex: Exception) {
            ""
        }
    }

    private fun getEntryContent(entry: ZipEntry): String {
        zipFile.getInputStream(entry).use { input ->
            val bytes = ByteArray(entry.size.toInt())
            val bis = BufferedInputStream(input)
            val dis = DataInputStream(bis)
            dis.readFully(bytes)
            return bytes.decodeToString()
        }
    }

    @Throws(IOException::class)
    override fun getAllCertificateData(): List<CertificateFile> {
        val enu = zipFile.entries()
        val list: MutableList<CertificateFile> = ArrayList()
        while (enu.hasMoreElements()) {
            val ne = enu.nextElement()
            if (ne.isDirectory) {
                continue
            }
            val name = ne.name.uppercase(Locale.getDefault())
            if (name.endsWith(".RSA") || name.endsWith(".DSA")) {
                list.add(CertificateFile(name, Inputs.readAllAndClose(zipFile.getInputStream(ne))))
            }
        }
        return list
    }

    @Throws(IOException::class)
    override fun getFileData(path: String): ByteArray? {
        val entry = zipFile.getEntry(path) ?: return null
        val inputStream = zipFile.getInputStream(entry)
        return Inputs.readAllAndClose(inputStream)
    }

    @Throws(IOException::class)
    override fun fileData(): ByteBuffer {
        fileChannel = FileInputStream(file).channel
        return fileChannel!!.map(FileChannel.MapMode.READ_ONLY, 0, fileChannel!!.size())
    }


    @Deprecated("using google official ApkVerifier of apksig lib instead.")
    @Throws(IOException::class)
    override fun verifyApk(): ApkSignStatus {
        zipFile.getEntry("META-INF/MANIFEST.MF") ?: return ApkSignStatus.notSigned
        JarFile(file).use { jarFile ->
            val entries = jarFile.entries()
            val buffer = ByteArray(8192)
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (e.isDirectory)
                    continue
                try {
                    jarFile.getInputStream(e).use { `in` ->
                        // Read in each jar entry. A security exception will be thrown if a signature/digest check fails.
                        var count: Int
                        while (`in`.read(buffer, 0, buffer.size).also { count = it } != -1) {
                            // Don't care
                        }
                    }
                } catch (se: SecurityException) {
                    return ApkSignStatus.incorrect
                }
            }
        }
        return ApkSignStatus.signed
    }

    @Throws(IOException::class)
    override fun close() {
        Closeable { super@ApkFile.close() }.use { zipFile.use { fileChannel.use { } } }
    }
}