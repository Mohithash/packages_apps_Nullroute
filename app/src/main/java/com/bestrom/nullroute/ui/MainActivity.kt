package com.bestrom.nullroute.ui

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.R
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomnavigation.BottomNavigationView

/**
 * The four Phase 1 screens: Home, Profile, Update, Diagnostics.
 *
 * Views and `findViewById`, no Compose and no ViewBinding — Soong supports none
 * of the three, and this app is built by Soong.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var toolbar: MaterialToolbar
    private lateinit var nav: BottomNavigationView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        toolbar = findViewById(R.id.toolbar)
        nav = findViewById(R.id.bottom_nav)

        nav.setOnItemSelectedListener { item ->
            select(tabForMenuId(item.itemId), fromUser = true)
            true
        }

        if (savedInstanceState == null) {
            select(intent.getIntExtra(EXTRA_OPEN_TAB, TAB_HOME), fromUser = false)
        }
    }

    /** The degraded-state notification deep-links straight into Diagnostics. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        select(intent.getIntExtra(EXTRA_OPEN_TAB, TAB_HOME), fromUser = false)
    }

    private fun select(tab: Int, fromUser: Boolean) {
        val fragment: Fragment = when (tab) {
            TAB_PROFILE -> ProfileFragment()
            TAB_UPDATE -> UpdateFragment()
            TAB_DIAGNOSTICS -> DiagnosticsFragment()
            else -> HomeFragment()
        }
        toolbar.setTitle(titleForTab(tab))

        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment)
            .commit()

        if (!fromUser) {
            // Setting the checked item re-enters the listener, so only do it when
            // the change came from somewhere other than the navigation bar.
            nav.menu.findItem(menuIdForTab(tab))?.isChecked = true
        }
    }

    private fun tabForMenuId(id: Int): Int = when (id) {
        R.id.nav_profile -> TAB_PROFILE
        R.id.nav_update -> TAB_UPDATE
        R.id.nav_diagnostics -> TAB_DIAGNOSTICS
        else -> TAB_HOME
    }

    private fun menuIdForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.id.nav_profile
        TAB_UPDATE -> R.id.nav_update
        TAB_DIAGNOSTICS -> R.id.nav_diagnostics
        else -> R.id.nav_home
    }

    private fun titleForTab(tab: Int): Int = when (tab) {
        TAB_PROFILE -> R.string.tab_profile
        TAB_UPDATE -> R.string.tab_update
        TAB_DIAGNOSTICS -> R.string.tab_diagnostics
        else -> R.string.app_name
    }

    companion object {
        const val EXTRA_OPEN_TAB = "com.bestrom.nullroute.extra.OPEN_TAB"

        const val TAB_HOME = 0
        const val TAB_PROFILE = 1
        const val TAB_UPDATE = 2
        const val TAB_DIAGNOSTICS = 3
    }
}
