package com.mrvinni.library.antivirus

import android.content.Context
import android.content.pm.PackageInstaller
import android.graphics.drawable.Drawable
import java.io.Serializable
import java.text.SimpleDateFormat
import java.util.*
import kotlin.collections.ArrayList

class AppInf : Serializable {

    lateinit var appName: String
    lateinit var appPackage: String

    lateinit var apkPath: String
    var apkSize: Double = 0.0

    var installerPackage: String? = null
    var installerSource: Int = 0

    var timeInstalled: Long = 0
    var timeUpdated: Long = 0

    var canBeDeviceAdmin = false

    var isLaunchable = true
    var isSystem = false

    var permissions: ArrayList<Permission> = ArrayList()

    var activities: ArrayList<String> = ArrayList()
    var services: ArrayList<String> = ArrayList()

    fun getDateInstalled(): String {
        val date = Date(timeInstalled)
        return SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(date)
    }

    fun getDateUpdated(): String {
        val date = Date(timeUpdated)
        return SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(date)
    }

    fun openApkFile(): ApkFile {
        return ApkFile(apkPath)
    }

    fun hasDangerousPermissions(): Boolean {
        return permissions.any { it.isAtLeastDangerous() }
    }

    fun hasTrustedInstallSource(): Boolean {
        return when {
            isSystem -> true
            installerSource == PackageInstaller.PACKAGE_SOURCE_STORE -> true
            installerSource == PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE -> false
            installerSource == PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE -> false
            else -> installerPackage == "com.android.vending"
        }
    }

    fun getIcon(context: Context): Drawable {
        return context.packageManager.getApplicationIcon(appPackage);
    }

    override fun toString(): String {
        return "Name: $appName Installer: $installerPackage Source: $installerSource IsLaunch $isLaunchable IsSystem $isSystem"
    }

}