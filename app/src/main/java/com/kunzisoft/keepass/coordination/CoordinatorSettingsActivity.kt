/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.os.Build
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AlertDialog
import androidx.activity.result.contract.ActivityResultContracts
import kotlin.concurrent.thread
import java.io.IOException

/** Basic configuration for the opt-in native file provider; no separate launcher. */
class CoordinatorSettingsActivity : AppCompatActivity() {
    private enum class ExportKind { LOCAL_RECOVERY, CURRENT_SERVER }
    private data class ExportRequest(val kind: ExportKind, val identity: String)
    private var pendingExport: ExportRequest? = null

    private val createEncryptedDocument =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri: Uri? ->
            val request = pendingExport
            pendingExport = null
            if (uri != null && request != null) exportToDocument(uri, request)
        }

    private fun exportToDocument(destination: Uri, request: ExportRequest) {
        val appContext = applicationContext
        thread(name = "keysafe-encrypted-kdbx-export") {
            try {
                // Settings may change while the file picker is open. Never mix databases.
                val config = CoordinatorConfiguration.get(appContext)
                    ?: throw IOException("Coordinator configuration missing")
                if (CoordinatorConflictCopies.identity(config) != request.identity)
                    throw IOException("Coordinator identity changed")
                val encrypted = when (request.kind) {
                    ExportKind.LOCAL_RECOVERY ->
                        CoordinatorConflictCopies.readLocal(appContext.filesDir, request.identity).bytes
                    ExportKind.CURRENT_SERVER ->
                        KdbxCoordinatorClient(config.url, config.id, config.token, "android-export")
                            .use { it.downloadReadOnly() }
                            ?: throw IOException("No server KDBX exists")
                }
                // Never fall back to cached bytes for the 'server' export.
                // A user-selected destination may be managed by external software.
                val stream = appContext.contentResolver.openOutputStream(destination, "w")
                    ?: throw IOException("Cannot open export destination")
                stream.use { it.write(encrypted); it.flush() }
                runOnUiThread {
                    Toast.makeText(this, "Encrypted KDBX exported. Original retained.", Toast.LENGTH_LONG).show()
                }
            } catch (_: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "Export failed. Original recovery copy was not changed.",
                        Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun beginExport(kind: ExportKind) {
        try {
            val config = CoordinatorConfiguration.get(this)
                ?: throw IOException("Coordinator not configured")
            val identity = CoordinatorConflictCopies.identity(config)
            if (kind == ExportKind.LOCAL_RECOVERY &&
                AtomicRecoveryStore.find(filesDir, identity) == null) {
                Toast.makeText(this, "No unsynchronized local KDBX exists", Toast.LENGTH_LONG).show()
                return
            }
            AlertDialog.Builder(this)
                .setTitle("Export encrypted KDBX")
                .setMessage("This saves a complete encrypted password database to a location " +
                    "you choose. Keep it private. Exporting does not merge databases, " +
                    "discard pending changes, or replace the server version.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Choose location") { _, _ ->
                    pendingExport = ExportRequest(kind, identity)
                    createEncryptedDocument.launch(if (kind == ExportKind.LOCAL_RECOVERY)
                        "keysafe-local-unsynchronized.kdbx" else "keysafe-server-current.kdbx")
                }
                .show()
        } catch (_: Exception) {
            Toast.makeText(this, "Cannot prepare encrypted KDBX export", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val space = (20 * resources.displayMetrics.density).toInt()
            setPadding(space, space, space, space)
        }
        fun field(label: String, secret: Boolean = false): EditText {
            form.addView(TextView(this).apply { text = label })
            return EditText(this).apply {
                setSingleLine(true)
                if (secret) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                form.addView(this)
            }
        }
        val url = field("HTTPS coordinator URL")
        val id = field("Database ID")
        val token = field("Access token (leave blank to keep saved token)", true)
        val previous = runCatching { CoordinatorConfiguration.get(this) }.getOrNull()
        url.setText(previous?.url ?: "")
        id.setText(previous?.id ?: "")
        val offline = CheckBox(this).apply {
            text = "Allow encrypted offline cache for this shared KDBX"
            isChecked = previous?.enableOfflineCache ?: false
        }
        form.addView(offline)
        val explanation = TextView(this).apply {
            text = "Select Coordinated KDBX in the Android file picker after saving. " +
                "If offline cache is enabled, the app retains only encrypted KDBX bytes. " +
                "Offline changes remain on this device until safely published after reconnecting. " +
                "Conflicting changes require manual recovery. Only use test databases for now."
        }
        form.addView(explanation)
        form.addView(Button(this).apply {
            text = "Save connection"
            setOnClickListener {
                try {
                    val secret = token.text.toString().ifBlank { previous?.token.orEmpty() }
                    CoordinatorConfiguration.put(this@CoordinatorSettingsActivity,
                        CoordinatorConfiguration.Config(url.text.toString().trim(), id.text.toString().trim(), secret,
                            offline.isChecked))
                    Toast.makeText(this@CoordinatorSettingsActivity, "Connection saved", Toast.LENGTH_SHORT).show()
                    finish()
                } catch (e: Exception) {
                    Toast.makeText(this@CoordinatorSettingsActivity,
                        "Unable to save coordinator configuration", Toast.LENGTH_LONG).show()
                }
            }
        })
        form.addView(TextView(this).apply {
            text = "Conflict recovery: export BOTH versions before attempting any manual merge. " +
                "Neither export removes pending changes, and the server is never overwritten here."
        })
        form.addView(Button(this).apply {
            text = "Export unsynchronized local KDBX"
            setOnClickListener { beginExport(ExportKind.LOCAL_RECOVERY) }
        })
        form.addView(Button(this).apply {
            text = "Export current server KDBX"
            setOnClickListener { beginExport(ExportKind.CURRENT_SERVER) }
        })
        val scroll = ScrollView(this).apply { addView(form) }
        setContentView(scroll, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT))
        if (Build.VERSION.SDK_INT < 23) {
            Toast.makeText(this, "Android 6+ required", Toast.LENGTH_LONG).show()
            finish()
        }
    }
}
