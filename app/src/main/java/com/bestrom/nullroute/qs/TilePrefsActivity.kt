package com.bestrom.nullroute.qs

import android.content.Context
import android.os.Bundle
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SwitchCompat
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.Paths

/**
 * What the Quick Settings tile does when it is tapped.
 *
 * ## Why this screen exists at all
 *
 * The tile's default is a straight pause/resume, which is the right default and
 * the wrong one for a shared or unlocked-in-public phone: the shade is reachable
 * without authentication on most lock screens, so one tap by anyone holding the
 * device can switch filtering off. "Open Nullroute" and "ask first" are the two
 * ways to close that, and they are choices rather than a policy because the
 * threat model is the user's, not ours.
 *
 * ## Why the preferences are DE-backed and read through [TilePrefs]
 *
 * `TileService.onClick` can run before the first unlock, where credential-
 * encrypted storage does not exist. These three values therefore live in the same
 * device-encrypted preference store the boot receiver and the watchdog use.
 * [TilePrefs] is the only reader, so the tile service never has to know where
 * they are kept.
 */
class TilePrefsActivity : AppCompatActivity() {

    private lateinit var actionGroup: RadioGroup
    private lateinit var confirm: SwitchCompat
    private lateinit var confirmDetail: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tileprefs)
        setTitle(R.string.qsp_title)

        actionGroup = findViewById(R.id.qsp_action_group)
        confirm = findViewById(R.id.qsp_confirm)
        confirmDetail = findViewById(R.id.qsp_confirm_detail)

        actionGroup.check(
            if (TilePrefs.action(this) == TilePrefs.ACTION_OPEN) R.id.qsp_action_open
            else R.id.qsp_action_toggle
        )
        confirm.isChecked = TilePrefs.confirmBeforePause(this)
        syncConfirmEnabled()

        actionGroup.setOnCheckedChangeListener { _, checkedId ->
            val action =
                if (checkedId == R.id.qsp_action_open) TilePrefs.ACTION_OPEN
                else TilePrefs.ACTION_TOGGLE
            TilePrefs.setAction(this, action)
            syncConfirmEnabled()
            saved()
        }

        confirm.setOnCheckedChangeListener { _, isChecked ->
            TilePrefs.setConfirmBeforePause(this, isChecked)
            saved()
        }
    }

    /**
     * "Ask before pausing" only means something when a tap pauses. Left enabled
     * under "Open Nullroute" it would be a switch with no effect, which is how a
     * settings screen loses the user's trust in the rest of its switches.
     */
    private fun syncConfirmEnabled() {
        val togglesFromTile = TilePrefs.action(this) == TilePrefs.ACTION_TOGGLE
        confirm.isEnabled = togglesFromTile
        confirmDetail.isEnabled = togglesFromTile
    }

    private fun saved() {
        Toast.makeText(this, R.string.qsp_saved, Toast.LENGTH_SHORT).show()
    }

    /**
     * The tile's preferences, readable before first unlock.
     *
     * Kept here rather than in [com.bestrom.nullroute.data.Settings] because
     * nothing outside the tile reads them, and because `Settings` deliberately
     * holds no copy of anything the control page already owns — these are pure UI
     * behaviour, with no representation in `control.bin` at all.
     */
    object TilePrefs {

        const val ACTION_TOGGLE = 0
        const val ACTION_OPEN = 1

        private const val PREFS = "nullroute_tile"
        private const val KEY_ACTION = "tile_action"
        private const val KEY_CONFIRM = "tile_confirm"

        private fun prefs(context: Context) =
            Paths.de(context).getSharedPreferences(PREFS, Context.MODE_PRIVATE)

        fun action(context: Context): Int =
            prefs(context).getInt(KEY_ACTION, ACTION_TOGGLE)

        fun setAction(context: Context, value: Int) {
            prefs(context).edit().putInt(KEY_ACTION, value).apply()
        }

        fun confirmBeforePause(context: Context): Boolean =
            prefs(context).getBoolean(KEY_CONFIRM, false)

        fun setConfirmBeforePause(context: Context, value: Boolean) {
            prefs(context).edit().putBoolean(KEY_CONFIRM, value).apply()
        }

        /**
         * Whether a tap may pause without any further interaction.
         *
         * One call so the tile has a single question to ask, and so the two
         * settings cannot be combined inconsistently at the two call sites.
         */
        fun tapMayPauseSilently(context: Context): Boolean =
            action(context) == ACTION_TOGGLE && !confirmBeforePause(context)
    }
}
