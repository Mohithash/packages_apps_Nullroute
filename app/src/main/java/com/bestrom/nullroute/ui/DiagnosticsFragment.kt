package com.bestrom.nullroute.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.bestrom.nullroute.NullrouteApp
import com.bestrom.nullroute.R
import com.bestrom.nullroute.core.ControlPage
import com.bestrom.nullroute.core.Native
import com.bestrom.nullroute.core.Paths
import com.bestrom.nullroute.core.Probes
import com.bestrom.nullroute.core.SysProp
import com.bestrom.nullroute.data.ProfileStore
import com.bestrom.nullroute.data.Settings
import com.bestrom.nullroute.job.DeviceConfigFixups
import com.google.android.material.button.MaterialButton
import java.io.File

/**
 * Diagnostics: every signal, with its source named, and nothing inferred.
 *
 * This screen is what makes the rest of the product debuggable on a device you
 * cannot attach a debugger to. It deliberately shows raw values — the exact
 * `sys.nullroute.filter` string, the exact mmap error, the process's supplementary
 * groups — because the failures that matter here are all of the shape "success
 * and failure look identical from userspace" (SPEC §10.7), and only the raw
 * values distinguish them.
 *
 * No domains are shown, so a diagnostics screenshot leaks no browsing history.
 */
class DiagnosticsFragment : Fragment() {

    private val main = Handler(Looper.getMainLooper())

    private lateinit var list: RecyclerView
    private lateinit var copyButton: MaterialButton
    private val items = ArrayList<Item>()
    private val adapter = DiagAdapter(items)

    sealed class Item {
        data class Header(val title: String) : Item()
        data class Row(val key: String, val value: String) : Item()
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View = inflater.inflate(R.layout.fragment_diagnostics, container, false)

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        list = view.findViewById(R.id.diag_list)
        copyButton = view.findViewById(R.id.diag_copy)
        list.layoutManager = LinearLayoutManager(requireContext())
        list.adapter = adapter
        copyButton.setOnClickListener { copyAll() }
    }

    override fun onResume() {
        super.onResume()
        collect()
    }

    private fun collect() {
        val context = requireContext().applicationContext
        NullrouteApp.io.execute {
            val collected = gather(context)
            main.post {
                if (!isAdded) return@post
                items.clear()
                items.addAll(collected)
                adapter.notifyDataSetChanged()
            }
        }
    }

    private fun gather(context: android.content.Context): List<Item> {
        val out = ArrayList<Item>()

        // ---- health -------------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_health))
        val health = runCatching { Probes.sample() }.getOrNull()
        // "no answer" and "not run" are different diagnoses and must not share a
        // string: Probes.sample skips probe A whenever the kill switch is set or
        // the mode is not ENFORCE, because nr_evaluate() returns PASS before the
        // redirect table in both cases. Reporting a skipped probe as a failed one
        // sends the reader hunting for a broken hook that is merely switched off.
        out += Item.Row(
            "idx-probe",
            health?.let {
                when {
                    it.resolverHookLive -> "${Probes.IDX_EXPECT} OK"
                    it.killSwitch -> "not run (kill switch)"
                    it.mode != ControlPage.MODE_ENFORCE -> "not run (mode=${modeName(it.mode)})"
                    else -> "no answer"
                }
            } ?: "not sampled",
        )
        out += Item.Row(
            "hosts-probe",
            health?.let { if (it.hostsLayerLive) "${Probes.HOSTS_EXPECT} OK" else "no answer" }
                ?: "not sampled",
        )
        out += Item.Row("status", health?.status()?.name ?: "UNKNOWN")
        out += Item.Row(Probes.PROP_FILTER_STATE, SysProp.get(Probes.PROP_FILTER_STATE, "(unset)"))
        out += Item.Row(Probes.PROP_SEED, SysProp.get(Probes.PROP_SEED, "(unset)"))

        // ---- switches ------------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_switches))
        out += Item.Row(Probes.PROP_KILL, SysProp.get(Probes.PROP_KILL, "0"))
        out += Item.Row(ControlPage.PROP_MODE, SysProp.get(ControlPage.PROP_MODE, "(unset)"))
        // The boot-loop breaker's state. fail_streak reaching 3 quarantines the
        // index at the next post-fs-data, so seeing 1 or 2 here is the warning
        // that something is restarting the device before the app can disarm it.
        out += Item.Row(Probes.PROP_FAIL_STREAK, SysProp.get(Probes.PROP_FAIL_STREAK, "0"))
        out += Item.Row(Probes.PROP_BOOT_OK, SysProp.get(Probes.PROP_BOOT_OK, "0"))

        // ---- control page --------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_control))
        val mapped = ControlPage.open()
        out += Item.Row("control.bin", if (mapped) "mapped rw" else (ControlPage.lastError ?: "not mapped"))
        if (mapped) {
            val t = ControlPage.telemetry()
            out += Item.Row("mode", modeName(ControlPage.mode))
            out += Item.Row("response_mode", responseName(ControlPage.responseMode))
            out += Item.Row("want_generation", ControlPage.wantGeneration.toString())
            out += Item.Row("mapped_generation", t.mappedGeneration.toString())
            out += Item.Row("filter_abi", if (t.filterAbi == 0) "0 (resolver has not reported)" else t.filterAbi.toString())
            out += Item.Row("q_total / q_blocked", "${t.queriesTotal} / ${t.queriesBlocked}")
            out += Item.Row("map_errors", t.mapErrors.toString())
            out += Item.Row("ring_drops", t.ringDrops.toString())
            out += Item.Row("fault_count", t.faultCount.toString())
            out += Item.Row("config_epoch", ControlPage.configEpoch.toString())
        }

        // ---- index ---------------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_index))
        out += Item.Row("libnrjni", if (Native.available) "loaded" else "NOT LOADED")
        out += fileRow("current.nrdx", Paths.currentIndex)
        out += fileRow("previous.nrdx", Paths.previousIndex)
        if (Paths.quarantineIndex.exists()) {
            // Present only after three failed boots. It is the single most
            // important thing on this screen when it exists.
            out += fileRow("quarantine.nrdx", Paths.quarantineIndex)
        }
        if (Native.available && Paths.currentIndex.isFile) {
            val info = Native.verify(Paths.currentIndex.absolutePath)
            out += Item.Row("verify", if (info.ok) "OK" else "FAILED: ${info.error}")
            if (info.ok) {
                out += Item.Row("generation", info.generation.toString())
                out += Item.Row("format", "v${info.formatVersion}")
                out += Item.Row("sha256", if (info.sha256Ok) "OK" else "MISMATCH")
                out += Item.Row(
                    "idx-probe redirect",
                    if (info.probePresent) info.probeAddress ?: "present" else "MISSING",
                )
                out += Item.Row(
                    "entries",
                    "${info.blockCount} block / ${info.allowCount} allow / " +
                        "${info.redirectCount} redirect",
                )
            }
        }

        // ---- L0 hosts ------------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_hosts))
        val hosts = Paths.hostsFile
        out += Item.Row("/system/etc/hosts", if (hosts.isFile) "${hosts.length()} bytes" else "missing")
        out += Item.Row("probe line", if (hostsProbePresent(hosts)) "present" else "absent")

        // ---- storage and privileges -----------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_storage))
        out += Item.Row(Paths.misc.path, if (Paths.misc.isDirectory) "present" else "MISSING")
        out += Item.Row("index/ ctl/ priv/", if (Paths.stateTreeReady()) "present" else "INCOMPLETE")
        out += Item.Row("priv writable", if (Paths.buildScratch.canWrite() || Paths.ensureAppDirs()) "yes" else "no")
        out += Item.Row("uid", Process.myUid().toString())
        // AID_MISC (9998) must appear here. It arrives via the <group gid="misc"/>
        // mapping on com.bestrom.nullroute.permission.STATE; without it every
        // open() under /data/misc/nullroute is EACCES before SELinux is consulted.
        out += Item.Row("groups", supplementaryGroups())

        // ---- configuration ---------------------------------------------------
        out += Item.Header(context.getString(R.string.diag_header_config))
        val profile = ProfileStore.activeProfile(context)
        out += Item.Row("profile", "${profile.displayName} (${profile.enabledSources.size} sources)")
        val record = Settings.lastUpdate(context)
        out += Item.Row(
            "last update",
            if (!record.everRan) "never" else "${if (record.ok) "ok" else "failed"} — ${record.message}",
        )
        out += Item.Row(
            "close_quic_connection",
            DeviceConfigFixups.getProperty("tethering", "close_quic_connection") ?: "(unset)",
        )

        return out
    }

    private fun fileRow(label: String, file: File): Item.Row = Item.Row(
        label,
        if (file.isFile) "${file.length() / 1024} KiB" else "absent",
    )

    /**
     * Looks for the L0 probe line without reading the whole file into memory —
     * the shipped hosts file is ~56 KB today but nothing stops a future build
     * from growing it.
     */
    private fun hostsProbePresent(hosts: File): Boolean = runCatching {
        if (!hosts.isFile) return false
        hosts.useLines { lines -> lines.any { it.contains(Probes.HOSTS) } }
    }.getOrDefault(false)

    private fun supplementaryGroups(): String = runCatching {
        File("/proc/self/status").useLines { lines ->
            lines.firstOrNull { it.startsWith("Groups:") }
                ?.removePrefix("Groups:")?.trim()
                ?: "(unreadable)"
        }
    }.getOrDefault("(unreadable)")

    private fun modeName(mode: Int): String = when (mode) {
        ControlPage.MODE_ENFORCE -> "0 ENFORCE"
        ControlPage.MODE_PAUSED -> "1 PAUSED"
        ControlPage.MODE_OFF -> "2 OFF"
        else -> mode.toString()
    }

    private fun responseName(value: Int): String = when (value) {
        ControlPage.RESP_NONAME -> "0 EAI_NONAME"
        ControlPage.RESP_NODATA -> "1 EAI_NODATA"
        ControlPage.RESP_SINKHOLE -> "2 sinkhole"
        else -> value.toString()
    }

    private fun copyAll() {
        val text = items.joinToString("\n") { item ->
            when (item) {
                is Item.Header -> "\n== ${item.title} =="
                is Item.Row -> "${item.key}: ${item.value}"
            }
        }
        val clipboard = requireContext().getSystemService(ClipboardManager::class.java)
        clipboard?.setPrimaryClip(ClipData.newPlainText("Nullroute diagnostics", text))
        Toast.makeText(requireContext(), R.string.diag_copied, Toast.LENGTH_SHORT).show()
    }

    private class DiagAdapter(private val items: List<Item>) :
        RecyclerView.Adapter<RecyclerView.ViewHolder>() {

        class HeaderHolder(view: View) : RecyclerView.ViewHolder(view) {
            val title: TextView = view.findViewById(R.id.header_title)
        }

        class RowHolder(view: View) : RecyclerView.ViewHolder(view) {
            val key: TextView = view.findViewById(R.id.row_title)
            val value: TextView = view.findViewById(R.id.row_detail)
        }

        override fun getItemViewType(position: Int): Int =
            if (items[position] is Item.Header) TYPE_HEADER else TYPE_ROW

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
            val inflater = LayoutInflater.from(parent.context)
            return if (viewType == TYPE_HEADER) {
                HeaderHolder(inflater.inflate(R.layout.item_header, parent, false))
            } else {
                RowHolder(inflater.inflate(R.layout.item_row, parent, false))
            }
        }

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
            when (val item = items[position]) {
                is Item.Header -> (holder as HeaderHolder).title.text = item.title
                is Item.Row -> (holder as RowHolder).let {
                    it.key.text = item.key
                    it.value.text = item.value
                }
            }
        }

        private companion object {
            const val TYPE_HEADER = 0
            const val TYPE_ROW = 1
        }
    }
}
