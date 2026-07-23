package org.kyberpipe.client

object QrNative {
    init {
        System.loadLibrary("core_crypto")
    }

    external fun decodeQrCode(
        yBytes: ByteArray,
        width: Int,
        height: Int,
        stride: Int,
        rotation: Int
    ): String?
}
