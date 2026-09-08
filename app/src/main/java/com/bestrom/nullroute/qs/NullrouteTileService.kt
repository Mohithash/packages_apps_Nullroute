package com.bestrom.nullroute.qs

import android.graphics.drawable.Icon
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.job.HealthWatchdog

/**
 * Quick Settings tile: pause and resume, and a status line.
 *
 * Pause is genuinely instant here — one byte in a mapped page, live on the
 * resolver's very next query. Re-Malwack's equivalent copies a 36 MiB hosts file
 * to a backup and truncates the original, which is why its pause has a
 * perceptible cost and why its state can be left inconsistent by a kill at the
 * wrong moment.
 *
 * The subtitle reports the **last verified** status, never a live one. The tile
 * runs on the system UI's binder thread and the liveness probe is a DNS lookup
 * that can take seconds when it is failing — exactly when the user is most likely
 * to be looking at the tile. So the probe runs on a worker and the tile says
 * "last checked" rather than blocking to find out.
 */
class NullrouteTileService : TileService() {

    /** `updateTile()` belongs to the tile's own thread; workers post back here. */
    private val main = android.os.Handler(android.os.Looper.getMainLooper())

    override fun onStartListening() {
        super.onStartListening()
        ControlPage.open()
        render()
        // Refresh in the background so the next glance is current.
        NullrouteApp.io.execute {
            runCatching { HealthWatchdog.runCheck(applicationContext) }
            main.post { runCatching { render() } }
        }
    }

    override fun onClick() {
        super.onClick()
        if (!ControlPage.open()) {
            render()
            return
        }
        val next = if (ControlPage.mode == ControlPage.MODE_ENFORCE) {
            ControlPage.MODE_PAUSED
        } else {
            ControlPage.MODE_ENFORCE
        }
        ControlPage.setMode(next)
        render()
        NullrouteApp.io.execute {
            runCatching { HealthWatchdog.runCheck(applicationContext) }
            main.post { runCatching { render() } }
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        val mapped = ControlPage.isMapped
        val mode = if (mapped) ControlPage.mode else ControlPage.MODE_ENFORCE
        val lastStatus = runCatching {
            Probes.FilterStatus.valueOf(Settings.lastStatus(applicationContext))
        }.getOrDefault(Probes.FilterStatus.UNKNOWN)

        tile.icon = Icon.createWithResource(this, R.drawable.ic_nullroute)
        tile.label = getString(R.string.app_name)

        when {
            // Without the control page there is nothing to toggle, and offering a
            // switch that does nothing is worse than showing the tile as broken.
            !mapped -> {
                tile.state = Tile.STATE_UNAVAILABLE
                tile.subtitle = getString(R.string.tile_unavailable)
            }

            mode != ControlPage.MODE_ENFORCE -> {
                tile.state = Tile.STATE_INACTIVE
                tile.subtitle = getString(R.string.tile_paused)
            }

            // The kill switch is not ours to clear from a tile — it is a
            // persistent property that only takes effect at boot — so the tile
            // reports it and refuses to pretend a tap would help.
            lastStatus == Probes.FilterStatus.KILLED -> {
                tile.state = Tile.STATE_UNAVAILABLE
                tile.subtitle = getString(R.string.tile_killed)
            }

            else -> {
                tile.state = Tile.STATE_ACTIVE
                tile.subtitle = when (lastStatus) {
                    Probes.FilterStatus.PROTECTED,
                    Probes.FilterStatus.PROTECTED_NO_L0,
                    -> getString(R.string.tile_on)

                    Probes.FilterStatus.LIMITED_L0_ONLY -> getString(R.string.tile_limited)
                    Probes.FilterStatus.NOT_FILTERING -> getString(R.string.tile_not_filtering)
                    else -> getString(R.string.tile_checking)
                }
            }
        }
        runCatching { tile.updateTile() }
    }
}
