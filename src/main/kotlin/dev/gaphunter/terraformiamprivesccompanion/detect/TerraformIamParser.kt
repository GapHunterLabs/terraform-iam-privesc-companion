package dev.gaphunter.terraformiamprivesccompanion.detect

import dev.gaphunter.terraformiamprivesccompanion.model.FileIamFacts
import dev.gaphunter.terraformiamprivesccompanion.model.InlinePolicy
import dev.gaphunter.terraformiamprivesccompanion.model.PolicyAttachment
import dev.gaphunter.terraformiamprivesccompanion.model.PolicyDefinition
import dev.gaphunter.terraformiamprivesccompanion.model.RoleDeclaration
import dev.gaphunter.terraformiamprivesccompanion.model.TrustEdge

/**
 * Plain-text scanner (same reasoning as `terraform-iam-wildcard-
 * companion`'s `HclJsonEncodeScanner`: `jsonencode({...})`'s argument
 * is HCL object/list syntax, not real JSON, walked via brace-balancing
 * rather than a JSON parser) that extracts, from a SINGLE file's text,
 * every real IAM fact this plugin's project-wide graph needs:
 *
 * - `resource "aws_iam_role" "<name>"` declarations, plus any
 *   AssumeRole trust edge in its own `assume_role_policy`.
 * - `resource "aws_iam_policy" "<name>"` documents, flagged
 *   admin-equivalent or not.
 * - `resource "aws_iam_role_policy_attachment"` (attaches a managed
 *   policy, by literal ARN or by referencing an `aws_iam_policy`
 *   resource, to a role).
 * - `resource "aws_iam_role_policy"` (an inline policy body attached
 *   directly to a role, no separate resource to reference).
 *
 * **v0.1 scope, stated honestly:** a `role =`/`Principal.AWS =`
 * reference only resolves the direct HCL form
 * `aws_iam_role.<name>.(name|id|arn)` -- never a literal role name
 * string, never an interpolation through a local variable, never
 * `for_each`/`count`-generated resources (each real resource block
 * must appear textually once). A literal cross-account
 * `arn:aws:iam::<account>:role/<name>` in `Principal.AWS` is correctly
 * NOT resolved to an edge (no matching in-project resource to
 * escalate through anyway).
 */
object TerraformIamParser {

    private val ROLE_HEADER = Regex("""resource\s+"aws_iam_role"\s+"([\w-]+)"\s*\{""")
    private val POLICY_HEADER = Regex("""resource\s+"aws_iam_policy"\s+"([\w-]+)"\s*\{""")
    private val ATTACHMENT_HEADER = Regex("""resource\s+"aws_iam_role_policy_attachment"\s+"([\w-]+)"\s*\{""")
    private val INLINE_POLICY_HEADER = Regex("""resource\s+"aws_iam_role_policy"\s+"([\w-]+)"\s*\{""")

    private val ASSUME_ROLE_POLICY_CALL = Regex("""assume_role_policy\s*=\s*jsonencode\s*\(""")
    private val POLICY_CALL = Regex("""(?<!assume_role_)policy\s*=\s*jsonencode\s*\(""")
    private val STATEMENT_KEY = Regex(""""?Statement"?\s*=\s*\[""")

    private val ROLE_REF = Regex("""aws_iam_role\.([\w-]+)\.(?:name|id|arn)""")
    private val POLICY_ARN_REF = Regex("""aws_iam_policy\.([\w-]+)\.arn""")
    private val ROLE_ASSIGN = Regex("""role\s*=\s*""" + ROLE_REF.pattern)
    private val POLICY_ARN_ASSIGN_LITERAL = Regex(""""?policy_arn"?\s*=\s*"([^"]*)"""")
    private val POLICY_ARN_ASSIGN_REF = Regex(""""?policy_arn"?\s*=\s*""" + POLICY_ARN_REF.pattern)

    private val EFFECT_ALLOW = Regex(""""?Effect"?\s*=\s*"Allow"""")
    private val ACTION_STRING = Regex(""""?Action"?\s*=\s*"([^"]*)"""")
    private val ACTION_LIST = Regex(""""?Action"?\s*=\s*\[([^]]*)]""")
    private val RESOURCE_STRING = Regex(""""?Resource"?\s*=\s*"([^"]*)"""")
    private val RESOURCE_LIST = Regex(""""?Resource"?\s*=\s*\[([^]]*)]""")
    private val PRINCIPAL_AWS_REF = Regex("""Principal\s*=\s*\{[^}]*AWS\s*=\s*""" + ROLE_REF.pattern)

    fun parseFile(text: String, virtualPath: String): FileIamFacts {
        val roles = mutableListOf<RoleDeclaration>()
        val trustEdges = mutableListOf<TrustEdge>()
        val policyDefinitions = mutableListOf<PolicyDefinition>()
        val attachments = mutableListOf<PolicyAttachment>()
        val inlinePolicies = mutableListOf<InlinePolicy>()

        for (match in ROLE_HEADER.findAll(text)) {
            val name = match.groupValues[1]
            val braceStart = match.range.last
            val braceEnd = BalancedBraceMatcher.findMatchingClose(text, braceStart, '{', '}') ?: continue
            roles += RoleDeclaration(name, virtualPath, braceStart)

            val body = text.substring(braceStart, braceEnd + 1)
            for (statementText in statementsOf(body, ASSUME_ROLE_POLICY_CALL)) {
                if (!containsAction(statementText, "sts:AssumeRole")) continue
                val principalMatch = PRINCIPAL_AWS_REF.find(statementText) ?: continue
                trustEdges += TrustEdge(fromRole = principalMatch.groupValues[1], toRole = name)
            }
        }

        for (match in POLICY_HEADER.findAll(text)) {
            val name = match.groupValues[1]
            val braceStart = match.range.last
            val braceEnd = BalancedBraceMatcher.findMatchingClose(text, braceStart, '{', '}') ?: continue
            val body = text.substring(braceStart, braceEnd + 1)
            val isAdmin = statementsOf(body, POLICY_CALL).any { isAdminEquivalentStatement(it) }
            policyDefinitions += PolicyDefinition(name, isAdmin)
        }

        for (match in ATTACHMENT_HEADER.findAll(text)) {
            val braceStart = match.range.last
            val braceEnd = BalancedBraceMatcher.findMatchingClose(text, braceStart, '{', '}') ?: continue
            val body = text.substring(braceStart, braceEnd + 1)
            val roleName = ROLE_ASSIGN.find(body)?.groupValues?.get(1) ?: continue

            val refMatch = POLICY_ARN_ASSIGN_REF.find(body)
            if (refMatch != null) {
                attachments += PolicyAttachment(roleName, literalPolicyArn = null, referencedPolicyResourceName = refMatch.groupValues[1])
                continue
            }
            val literalMatch = POLICY_ARN_ASSIGN_LITERAL.find(body)
            if (literalMatch != null) {
                attachments += PolicyAttachment(roleName, literalPolicyArn = literalMatch.groupValues[1], referencedPolicyResourceName = null)
            }
        }

        for (match in INLINE_POLICY_HEADER.findAll(text)) {
            val braceStart = match.range.last
            val braceEnd = BalancedBraceMatcher.findMatchingClose(text, braceStart, '{', '}') ?: continue
            val body = text.substring(braceStart, braceEnd + 1)
            val roleName = ROLE_ASSIGN.find(body)?.groupValues?.get(1) ?: continue
            val isAdmin = statementsOf(body, POLICY_CALL).any { isAdminEquivalentStatement(it) }
            inlinePolicies += InlinePolicy(roleName, isAdmin)
        }

        return FileIamFacts(roles, trustEdges, policyDefinitions, attachments, inlinePolicies)
    }

    /** Finds the `jsonencode({ ... Statement = [ {...}, {...} ] ... })` call matched by [callHeader] inside [body] and returns the text of each individual statement object. */
    private fun statementsOf(body: String, callHeader: Regex): List<String> {
        val callMatch = callHeader.find(body) ?: return emptyList()
        var objStart = callMatch.range.last + 1
        while (objStart < body.length && body[objStart].isWhitespace()) objStart++
        if (objStart >= body.length || body[objStart] != '{') return emptyList()
        val objEnd = BalancedBraceMatcher.findMatchingClose(body, objStart, '{', '}') ?: return emptyList()
        val policyObject = body.substring(objStart, objEnd + 1)

        val statementMatch = STATEMENT_KEY.find(policyObject) ?: return emptyList()
        val listStart = statementMatch.range.last
        val listEnd = BalancedBraceMatcher.findMatchingClose(policyObject, listStart, '[', ']') ?: return emptyList()

        val statements = mutableListOf<String>()
        var i = listStart + 1
        while (i < listEnd) {
            val c = policyObject[i]
            if (c == '{') {
                val stmtEnd = BalancedBraceMatcher.findMatchingClose(policyObject, i, '{', '}')
                if (stmtEnd == null || stmtEnd > listEnd) break
                statements += policyObject.substring(i, stmtEnd + 1)
                i = stmtEnd + 1
            } else {
                i++
            }
        }
        return statements
    }

    private fun containsAction(statementText: String, action: String): Boolean {
        ACTION_STRING.find(statementText)?.let { return it.groupValues[1] == action }
        ACTION_LIST.find(statementText)?.let { match ->
            return match.groupValues[1].split(",").map { it.trim().trim('"') }.any { it == action }
        }
        return false
    }

    /** Effect="Allow" AND (Action=="*" or contains "*") AND (Resource=="*" or contains "*") -- the concrete admin-equivalent shape, never a guess from a partial wildcard. */
    private fun isAdminEquivalentStatement(statementText: String): Boolean {
        if (!EFFECT_ALLOW.containsMatchIn(statementText)) return false
        return fieldIsWildcard(statementText, ACTION_STRING, ACTION_LIST) && fieldIsWildcard(statementText, RESOURCE_STRING, RESOURCE_LIST)
    }

    private fun fieldIsWildcard(statementText: String, stringForm: Regex, listForm: Regex): Boolean {
        stringForm.find(statementText)?.let { return it.groupValues[1] == "*" }
        listForm.find(statementText)?.let { match ->
            return match.groupValues[1].split(",").map { it.trim().trim('"') }.any { it == "*" }
        }
        return false
    }
}
