/* SPDX-License-Identifier: GPL-3.0-or-later */
package com.kunzisoft.keepass.coordination

/**
 * Non-mutating group/entry topology preflight for a future credential-aware KDBX adapter.
 *
 * The adapter MUST provide a complete, verified snapshot. [recordSha256] MUST be the
 * SHA-256 of the complete canonical decrypted logical record (including history,
 * protected fields, attachments, metadata and deletion semantics). This code cannot
 * establish that completeness and MUST NOT be used as authority to write or publish.
 * Database-wide metadata, custom icons and DeletedObjects are not merged here.
 */
internal object ThreeWayKdbxTreePlan {
    enum class Kind { GROUP, ENTRY }
    enum class Source { UNCHANGED, LOCAL, REMOTE, IDENTICAL }

    data class Node(
        val id: String,
        val kind: Kind,
        val parentGroupId: String?,
        val recordSha256: String
    )

    data class Snapshot(val rootGroupId: String, val nodes: Map<String, Node>)
    data class Decision(val id: String, val source: Source)
    data class Result(val decisions: List<Decision>, val nodes: Map<String, Node>)

    private val sha256Pattern = Regex("[0-9a-f]{64}")

    /** All validation happens before a result is returned. Conflicts throw. */
    fun plan(base: Snapshot, local: Snapshot, remote: Snapshot): Result {
        require(base.rootGroupId == local.rootGroupId && base.rootGroupId == remote.rootGroupId) {
            "KDBX root UUID differs between base, local and remote"
        }
        validate(base)
        validate(local)
        validate(remote)

        val ids = (base.nodes.keys + local.nodes.keys + remote.nodes.keys).toSortedSet()
        val result = linkedMapOf<String, Node>()
        val decisions = ArrayList<Decision>(ids.size)
        for (id in ids) {
            val b = base.nodes[id]
            val l = local.nodes[id]
            val r = remote.nodes[id]
            // UUIDs must never silently change from group to entry or vice versa.
            require(listOfNotNull(b, l, r).map { it.kind }.distinct().size <= 1) {
                "KDBX node UUID reused for another node kind: $id"
            }
            val source: Source
            val selected: Node?
            when {
                l == r -> {
                    source = if (l == b) Source.UNCHANGED else Source.IDENTICAL
                    selected = l
                }
                l == b -> {
                    source = Source.REMOTE
                    selected = r
                }
                r == b -> {
                    source = Source.LOCAL
                    selected = l
                }
                else -> throw IllegalArgumentException("Unresolved KDBX node conflict: $id")
            }
            decisions.add(Decision(id, source))
            if (selected != null) result[id] = selected
        }

        // Individually valid snapshots can yield an invalid combined hierarchy.
        validate(Snapshot(base.rootGroupId, result))
        return Result(decisions, result.toMap())
    }

    private fun validate(snapshot: Snapshot) {
        val rootId = snapshot.rootGroupId
        require(rootId.isNotBlank()) { "Empty KDBX root UUID" }
        val root = snapshot.nodes[rootId]
        require(root?.kind == Kind.GROUP && root.parentGroupId == null) {
            "KDBX root missing, not a group, or has a parent"
        }
        for ((id, node) in snapshot.nodes) {
            require(id.isNotBlank() && id == node.id) { "KDBX node key/UUID mismatch" }
            require(sha256Pattern.matches(node.recordSha256)) {
                "KDBX node fingerprint is not SHA-256: $id"
            }
            if (id != rootId) {
                val parent = node.parentGroupId?.let { snapshot.nodes[it] }
                require(parent?.kind == Kind.GROUP) {
                    "KDBX node has missing/non-group parent: $id"
                }
            }
        }
        // Iterative ancestry check: bounded stack and no recursion on adversarial trees.
        val verified = HashSet<String>()
        verified.add(rootId)
        for ((id, node) in snapshot.nodes) {
            if (node.kind != Kind.GROUP || id in verified) continue
            val path = LinkedHashSet<String>()
            var current = id
            while (current !in verified) {
                require(path.add(current)) { "KDBX group ancestry cycle: $id" }
                current = snapshot.nodes[current]?.parentGroupId
                    ?: throw IllegalArgumentException("KDBX group has detached ancestor: $id")
            }
            verified.addAll(path)
        }
    }
}
