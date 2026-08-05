package org.kyberpipe.client.service

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM behavioral tests for the poll wire transport (verification-gap
 * remediation). These run WITHOUT an emulator: `PollTransport` now depends on
 * the [PollSettings] / [PollFfi] contracts, so the critical AUDIT #1 logic —
 * a SUCCESSFUL `processResponse` must reach the ENGINE-OWNED flow, and the
 * unpair signal must be set ONLY on an explicit desktop `is_paired:false` —
 * is exercised hermetically.
 *
 * NOTE: the production flow uses `MutableSharedFlow(extraBufferCapacity = 32)`
 * (replay = 0); the tests use `replay = 1` purely so a single late subscriber
 * (`flow.first()`) deterministically receives the emission — the regression
 * under test is that `processResponse` writes into the ENGINE-OWNED flow
 * object, not that it creates its own orphaned one (audit #1).
 */
class PollTransportTest {

    private class FakeSettings : PollSettings {
        override var pendingPairingConfirmation: Boolean = false
        override var isPaired: Boolean = true
        override var pairedDeviceName: String = ""
    }

    private class FakeFfi : PollFfi {
        override fun synchronizePacketBinary(peer: String): ByteArray = byteArrayOf(1)
        override fun generateRekeyAckBinaryPeek(peer: String): ByteArray? = null
        override fun processRekeyAckBinary(peer: String, tlv: ByteArray) {}
        override fun processSynchronize(peer: String, tlv: ByteArray) {}
        override fun decryptMessageBinary(peer: String, tlv: ByteArray): ByteArray =
            "remote-clip".toByteArray()
    }

    private fun baseResponse(): JSONObject = JSONObject().apply {
        put("is_paired", true)
        put("connection_status", "ACTIVE")
        put("connection_method", "LAN")
        put("connection_color", "green")
        put("pending_media_action", JSONObject.NULL)
        put("manifest", org.json.JSONArray())
    }

    /**
     * AUDIT #1 regression (CRITICAL): a SUCCESSFUL `processResponse` must reach
     * the engine-owned flow. Before the fix the transport emitted to its OWN
     * orphaned SharedFlow that the UI never subscribed to — the success path
     * was dead and the UI never rendered ACTIVE.
     */
    @Test
    fun successfulProcessResponseReachesEngineFlow() = runBlocking {
        val flow = MutableSharedFlow<KyberPipePollEngine.PollUpdate>(replay = 1)
        val settings = FakeSettings()
        val transport = PollTransport(settings = settings, updates = flow, requestSync = {})

        transport.processResponse("peer", baseResponse()) { _, _, _ -> null }
        val update = flow.first()

        assertEquals("ACTIVE", update.status)
        assertEquals("LAN", update.method)
        assertTrue("success path must report connected", update.connected)
        assertTrue(update.isPaired)
        assertFalse("no unpair signal on a healthy response", update.unpairSignal)
        assertFalse(update.pairingConfirmed)
    }

    /** AUDIT #1: the unpair signal is set ONLY when the desktop reports `is_paired:false`. */
    @Test
    fun explicitDesktopUnpairSetsUnpairSignal() = runBlocking {
        val flow = MutableSharedFlow<KyberPipePollEngine.PollUpdate>(replay = 1)
        val settings = FakeSettings().apply { isPaired = true }
        val transport = PollTransport(settings = settings, updates = flow, requestSync = {})

        val resp = baseResponse().apply { put("is_paired", false) }
        transport.processResponse("peer", resp) { _, _, _ -> null }
        val update = flow.first()

        assertTrue("explicit desktop unpair must set unpairSignal", update.unpairSignal)
        assertFalse("settings.isPaired must be cleared on explicit unpair", settings.isPaired)
        assertEquals("pairedDeviceName must be cleared on explicit unpair", "", settings.pairedDeviceName)
    }

    /** The two-phase pairing commit (audit #6): commit only when the desktop confirms. */
    @Test
    fun pairingConfirmedWhenDesktopConfirmsSas() = runBlocking {
        val flow = MutableSharedFlow<KyberPipePollEngine.PollUpdate>(replay = 1)
        val settings = FakeSettings().apply { pendingPairingConfirmation = true; isPaired = false }
        val transport = PollTransport(settings = settings, updates = flow, requestSync = {})

        val resp = baseResponse().apply { put("is_paired", true) }
        transport.processResponse("peer", resp) { _, _, _ -> null }
        val update = flow.first()

        assertTrue("pairingConfirmed must be true when the desktop confirms the SAS", update.pairingConfirmed)
        assertTrue("settings.isPaired must commit on confirmation", settings.isPaired)
        assertFalse(settings.pendingPairingConfirmation)
    }

    /**
     * AUDIT P1-1 (HIGH): the phone mirrors the producer-side frame cap — a clip
     * TLV whose size exceeds the shared UniFFI-exported MAX_MESSAGE_SIZE is
     * refused BEFORE it reaches the ratchet. The producer (desktop poll
     * handler) now refuses to encrypt clipboard payloads whose framing would
     * exceed the bound, so a payload beyond it can only come from a
     * broken/foreign producer.
     */
    @Test
    fun oversizedClipTlvIsRefusedBeforeRatchet() = runBlocking {
        val flow = MutableSharedFlow<KyberPipePollEngine.PollUpdate>(replay = 1)
        val settings = FakeSettings()
        val transport = PollTransport(settings = settings, updates = flow, requestSync = {})

        // The shared bound (1 MiB) is the UniFFI-exported constant; in the JVM
        // test it falls back to the documented value via runCatching.
        assertTrue(
            "a TLV at MAX_MESSAGE_SIZE + 1 must be refused",
            transport.refusesOversizedTlv(PollTransport.MAX_FRAME_BODY_SIZE + 1)
        )
        assertFalse(
            "a TLV exactly at MAX_MESSAGE_SIZE is still accepted",
            transport.refusesOversizedTlv(PollTransport.MAX_FRAME_BODY_SIZE)
        )
    }

    /** The two-phase pairing commit (audit #6): a rejection must NOT commit. */
    @Test
    fun pairingRejectedWhenDesktopRefuses() = runBlocking {
        val flow = MutableSharedFlow<KyberPipePollEngine.PollUpdate>(replay = 1)
        val settings = FakeSettings().apply { pendingPairingConfirmation = true; isPaired = false }
        val transport = PollTransport(settings = settings, updates = flow, requestSync = {})

        val resp = baseResponse().apply {
            put("is_paired", false)
            put("reason", "Not paired")
        }
        transport.processResponse("peer", resp) { _, _, _ -> null }
        val update = flow.first()

        assertFalse("must not commit on rejection", update.pairingConfirmed)
        assertFalse(settings.pendingPairingConfirmation)
        assertTrue("explicit rejection still surfaces unpairSignal", update.unpairSignal)
    }
}
