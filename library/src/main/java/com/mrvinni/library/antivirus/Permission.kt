package com.mrvinni.library.antivirus

import android.content.pm.PermissionInfo
import java.io.Serializable

class Permission : Serializable {

    companion object {
        const val ANDROID_PERMISSION = "android.permission."
    }

    lateinit var name: String
    lateinit var label: String
    lateinit var description: String

    var protectionLevel: Int = PermissionInfo.PROTECTION_NORMAL

    fun isCustom(): Boolean { return !name.startsWith(ANDROID_PERMISSION) }
    fun isAtLeastDangerous(): Boolean { return protectionLevel >= PermissionInfo.PROTECTION_DANGEROUS }

    fun isNormal(): Boolean { return protectionLevel == PermissionInfo.PROTECTION_NORMAL }
    fun isDangerous(): Boolean { return protectionLevel == PermissionInfo.PROTECTION_DANGEROUS }
    fun isSignature(): Boolean { return protectionLevel == PermissionInfo.PROTECTION_SIGNATURE }

    override fun toString(): String {
        return name
    }

}