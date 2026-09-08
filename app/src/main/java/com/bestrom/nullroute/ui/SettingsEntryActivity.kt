package com.bestrom.nullroute.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * The row Settings shows under **Network & internet**.
 *
 * Everything that makes the injection work is manifest metadata — the
 * `com.android.settings.category.ia.network` category, the title, the summary and
 * the icon — which Settings reads without ever starting us. This activity exists
 * only to be the thing that launches when the row is tapped, so it hands off to
 * [MainActivity] and disappears.
 *
 * `Theme.NoDisplay` plus `noHistory` and `excludeFromRecents` in the manifest
 * mean the user never sees this activity and never finds it in recents: the
 * transition from the Settings row to the app should look like one step, because
 * from the user's point of view it is.
 */
class SettingsEntryActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        startActivity(
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        )
        finish()
    }
}
