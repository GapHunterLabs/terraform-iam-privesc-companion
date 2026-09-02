package dev.gaphunter.terraformiamprivesccompanion.detect

import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Key
import com.intellij.psi.PsiManager
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope
import com.intellij.psi.util.CachedValue
import com.intellij.psi.util.CachedValueProvider
import com.intellij.psi.util.CachedValuesManager
import com.intellij.psi.util.PsiModificationTracker
import dev.gaphunter.terraformiamprivesccompanion.model.EscalationPath
import dev.gaphunter.terraformiamprivesccompanion.model.RoleDeclaration
import java.util.ArrayDeque

/**
 * Aggregates [TerraformIamParser]'s per-file facts across EVERY `.tf`
 * file in the project into one real directed graph (role -> roles it
 * can assume via a trust edge), then answers "can role X reach an
 * admin-equivalent role" via a genuine BFS with cycle protection (a
 * visited-set, never a fixed depth bound) -- the mechanism that makes
 * this plugin's Terraform IAM Wildcard predecessor's single-statement
 * check into a real cross-file escalation-path finder, matching how
 * PMapper's own graph model works, just applied statically to source
 * before `terraform apply` instead of a live AWS account.
 *
 * Cached per-project via [CachedValuesManager], invalidated on any PSI
 * change ([PsiModificationTracker.MODIFICATION_COUNT]) -- rebuilding
 * the whole-project graph on every keystroke across every `.tf` file
 * would make on-the-fly highlighting of a large project unusably slow.
 *
 * **v0.1 safety valve:** a project with more than [MAX_TF_FILES] `.tf`
 * files skips whole-project graph analysis entirely (returns an empty
 * graph) rather than attempting it -- documented honestly rather than
 * silently hanging on a pathologically large monorepo.
 */
object ProjectIamGraphBuilder {

    const val MAX_TF_FILES = 300
    private const val MAX_FILE_LENGTH = 500_000

    private val CACHE_KEY: Key<CachedValue<IamProjectGraph>> = Key.create("terraformIamPrivescCompanion.graph")

    class IamProjectGraph(
        val roleDeclarations: Map<String, RoleDeclaration>,
        private val adjacency: Map<String, List<String>>,
        private val adminRoles: Set<String>,
    ) {
        fun isAdmin(roleName: String): Boolean = roleName in adminRoles

        /** Shortest real path (BFS, cycle-safe) from [startRole] to any admin-equivalent role, or null if none exists. */
        fun findEscalationPath(startRole: String): EscalationPath? {
            if (isAdmin(startRole)) return null
            val visited = mutableSetOf(startRole)
            val parent = mutableMapOf<String, String>()
            val queue = ArrayDeque<String>()
            queue.add(startRole)

            while (queue.isNotEmpty()) {
                val current = queue.poll()
                for (next in adjacency[current].orEmpty()) {
                    if (!visited.add(next)) continue
                    parent[next] = current
                    if (isAdmin(next)) {
                        val path = mutableListOf(next)
                        var walk = next
                        while (walk != startRole) {
                            walk = parent.getValue(walk)
                            path.add(walk)
                        }
                        return EscalationPath(path.asReversed())
                    }
                    queue.add(next)
                }
            }
            return null
        }
    }

    fun graphFor(project: Project): IamProjectGraph {
        val cached = CachedValuesManager.getManager(project).getCachedValue(
            project,
            CACHE_KEY,
            { CachedValueProvider.Result.create(computeGraph(project), PsiModificationTracker.MODIFICATION_COUNT) },
            false,
        )
        return cached
    }

    private fun computeGraph(project: Project): IamProjectGraph {
        val files = FilenameIndex.getAllFilesByExt(project, "tf", GlobalSearchScope.projectScope(project))
        if (files.size > MAX_TF_FILES) {
            return IamProjectGraph(emptyMap(), emptyMap(), emptySet())
        }

        val roleDeclarations = mutableMapOf<String, RoleDeclaration>()
        val adjacency = mutableMapOf<String, MutableList<String>>()
        val adminRoles = mutableSetOf<String>()
        val policyIsAdmin = mutableMapOf<String, Boolean>()
        val pendingAttachments = mutableListOf<Pair<String, String?>>() // roleName to referencedPolicyResourceName (literal-ARN attachments already resolved below)

        val psiManager = PsiManager.getInstance(project)
        for (virtualFile in files) {
            val text = psiManager.findFile(virtualFile)?.text ?: continue
            if (text.length > MAX_FILE_LENGTH) continue
            val path = virtualFile.path

            val facts = TerraformIamParser.parseFile(text, path)
            for (role in facts.roles) {
                roleDeclarations.putIfAbsent(role.name, role)
            }
            for (edge in facts.trustEdges) {
                adjacency.getOrPut(edge.fromRole) { mutableListOf() }.add(edge.toRole)
            }
            for (policy in facts.policyDefinitions) {
                policyIsAdmin[policy.resourceName] = policy.isAdminEquivalent
            }
            for (inline in facts.inlinePolicies) {
                if (inline.isAdminEquivalent) adminRoles += inline.roleName
            }
            for (attachment in facts.attachments) {
                if (attachment.literalPolicyArn != null) {
                    if (attachment.literalPolicyArn.endsWith("/AdministratorAccess")) {
                        adminRoles += attachment.roleName
                    }
                } else {
                    pendingAttachments += attachment.roleName to attachment.referencedPolicyResourceName
                }
            }
        }

        for ((roleName, policyResourceName) in pendingAttachments) {
            if (policyResourceName != null && policyIsAdmin[policyResourceName] == true) {
                adminRoles += roleName
            }
        }

        return IamProjectGraph(roleDeclarations, adjacency, adminRoles)
    }
}
