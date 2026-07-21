package org.kyberpipe.client.service

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log

class KyberTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState(isActive = true)
    }

    override fun onClick() {
        super.onClick()
        val tile = qsTile ?: return
        val isActive = tile.state == Tile.STATE_ACTIVE

        if (isActive) {
            val stopIntent = Intent(this, PipeService::class.java)
            stopService(stopIntent)
            updateTileState(isActive = false)
            Log.i("KyberTileService", "Kyberpipe daemon stopped via QS Tile.")
        } else {
            val startIntent = Intent(this, PipeService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
            updateTileState(isActive = true)
            Log.i("KyberTileService", "Kyberpipe daemon started via QS Tile.")
        }
    }

    private fun updateTileState(isActive: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (isActive) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (isActive) "Kyberpipe Active" else "Kyberpipe Stopped"
        tile.updateTile()
    }
}
