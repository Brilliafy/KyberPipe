package org.kyberpipe.client.crash

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

object CrashLogger {
    fun install(context: Context) {
        Thread.setDefaultUncaughtExceptionHandler { _, throwable ->
            saveCrashLog(context, throwable)
            android.os.Process.killProcess(android.os.Process.myPid())
            System.exit(10)
        }
    }

    fun getLatestCrashLog(context: Context): String? {
        val file = File(context.filesDir, "crash_log.txt")
        return if (file.exists()) file.readText() else null
    }

    private fun saveCrashLog(context: Context, throwable: Throwable) {
        try {
            val sw = StringWriter()
            val pw = PrintWriter(sw)
            throwable.printStackTrace(pw)
            val anonymized = anonymizeAndroidCrashLog(sw.toString())
            val file = File(context.filesDir, "crash_log.txt")
            file.writeText(anonymized)
        } catch (e: Exception) {
            Log.e("KyberPipe", "Failed to write crash log", e)
        }
    }

    private fun anonymizeAndroidCrashLog(rawTrace: String): String {
        var scrubbed = rawTrace
        // Scrub phone numbers (10+ digits)
        scrubbed = scrubbed.replace(Regex("\\+?[0-9]{10,}"), "[MASKED_PHONE_NUMBER]")
        // Scrub email addresses
        scrubbed = scrubbed.replace(Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"), "[MASKED_EMAIL]")
        // Scrub IP addresses
        scrubbed = scrubbed.replace(Regex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"), "[MASKED_IP]")
        // Scrub Android device serials/identifying fingerprints if any leak
        scrubbed = scrubbed.replace(Build.FINGERPRINT, "[MASKED_FINGERPRINT]")
        scrubbed = scrubbed.replace(Build.MODEL, "[MASKED_MODEL]")
        scrubbed = scrubbed.replace(Build.DEVICE, "[MASKED_DEVICE]")
        scrubbed = scrubbed.replace(Build.MANUFACTURER, "[MASKED_MANUFACTURER]")
        return scrubbed
    }
}
