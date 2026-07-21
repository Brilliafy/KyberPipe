package org.kyberpipe.client.security

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors

object BiometricAuthManager {

    fun authenticateStepUp(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val executor = Executors.newSingleThreadExecutor()
        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.i("KyberpipeBioAuth", "Biometric Step-Up Authorization Succeeded.")
                    activity.runOnUiThread { onSuccess() }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.w("KyberpipeBioAuth", "Biometric Step-Up Error ($errorCode): $errString")
                    activity.runOnUiThread { onError(errString.toString()) }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.w("KyberpipeBioAuth", "Biometric Step-Up Authentication Failed.")
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
