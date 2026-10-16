/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/** Basic configuration for the opt-in native file provider; no separate launcher. */
class CoordinatorSettingsActivity : AppCompatActivity() {
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
        setContentView(form, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        if (Build.VERSION.SDK_INT < 23) {
            Toast.makeText(this, "Android 6+ required", Toast.LENGTH_LONG).show()
            finish()
        }
    }
}
