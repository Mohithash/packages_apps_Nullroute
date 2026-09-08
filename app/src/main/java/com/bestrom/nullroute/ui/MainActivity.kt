package com.bestrom.nullroute.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.bestrom.nullroute.R
import com.bestrom.nullroute.qs.TilePrefsActivity
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.bottomnavigation.BottomNavigationView

/**
 * Four tabs — Home, Profile, Update, Diagnostics — plus a toolbar overflow for
 * the ten screens past them. A BottomNavigationView holds five destinations at
 * most, so the overflow is not a stylistic choice; the alternative is hiding
 * whole features behind a nav bar that cannot show them.
 *
 * Overflow destinations are PUSHED onto the back stack rather than swapped like
 * a tab, so `back` returns to the tab the user was on instead of exiting.
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

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_overflow, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val fragment: Fragment = when (item.itemId) {
            R.id.menu_rules -> RulesFragment()
            R.id.menu_query -> QueryFragment()
            R.id.menu_apps -> AppPolicyFragment()
            R.id.menu_categories -> CategoriesFragment()
            R.id.menu_sources -> SourceEditFragment()
            R.id.menu_log -> LogFragment()
            R.id.menu_deep -> DeepModeFragment()
            R.id.menu_selftest -> SelfTestFragment()
            R.id.menu_advanced -> AdvancedFragment()
            R.id.menu_settings -> SettingsFragment()
            else -> return super.onOptionsItemSelected(item)
        }
        push(fragment, item.title?.toString().orEmpty())
        return true
    }

    /**
     * Push a non-tab destination. Named in the back stack so a second tap on the
     * same overflow item does not stack a duplicate on top of itself.
     */
    private fun push(fragment: Fragment, title: String) {
        val tag = fragment.javaClass.simpleName
        supportFragmentManager.popBackStack(tag, 0)
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment, tag)
            .addToBackStack(tag)
            .commit()
        toolbar.title = title
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
