package dev.gaphunter.terraformiamprivesccompanion.model

/** One `resource "aws_iam_role" "<name>"` block found anywhere in the project. */
data class RoleDeclaration(
    val name: String,
    /** File-relative offset of the resource's own `{`, for anchoring a warning if this role turns out to be the start of an escalation path. */
    val fileVirtualPath: String,
    val declarationOffset: Int,
)

/**
 * A trust edge parsed from a role's `assume_role_policy`: [fromRole]
 * (the OTHER role named as `Principal.AWS` via a direct
 * `aws_iam_role.<name>.arn` reference) is trusted to call
 * `sts:AssumeRole` and become [toRole] (the role that OWNS this
 * assume_role_policy, i.e. the trust document is a resource-based
 * policy attached to [toRole] itself).
 *
 * **v0.1 simplification, stated honestly:** presence of the trust
 * relationship alone is treated as enough for the edge to exist --
 * this does not additionally cross-check that [fromRole] also holds
 * an identity-based `sts:AssumeRole` permission naming [toRole]'s ARN.
 * Real IAM requires both sides in general, but a trust policy this
 * broad is itself already the signal most real privilege-escalation
 * audits (PMapper's own graph model included) treat as the edge.
 */
data class TrustEdge(
    val fromRole: String,
    val toRole: String,
)

/** A `resource "aws_iam_policy" "<name>"` (a standalone, attachable policy document) and whether its own statements are admin-equivalent. */
data class PolicyDefinition(
    val resourceName: String,
    val isAdminEquivalent: Boolean,
)

/**
 * A `resource "aws_iam_role_policy_attachment"` -- attaches a policy to
 * [roleName], either by a literal managed-policy ARN
 * ([literalPolicyArn]) or by referencing a [PolicyDefinition] resource
 * by name ([referencedPolicyResourceName]). Exactly one of the two is
 * non-null.
 */
data class PolicyAttachment(
    val roleName: String,
    val literalPolicyArn: String?,
    val referencedPolicyResourceName: String?,
)

/** A `resource "aws_iam_role_policy"` (inline policy body, no separate resource to reference) attached directly to [roleName]. */
data class InlinePolicy(
    val roleName: String,
    val isAdminEquivalent: Boolean,
)

/** Everything this plugin's parser extracted from a single `.tf` file's text. */
data class FileIamFacts(
    val roles: List<RoleDeclaration>,
    val trustEdges: List<TrustEdge>,
    val policyDefinitions: List<PolicyDefinition>,
    val attachments: List<PolicyAttachment>,
    val inlinePolicies: List<InlinePolicy>,
)

/** One found escalation path, from [path].first() (not itself admin) to [path].last() (an admin-equivalent role), via direct AssumeRole trust edges. */
data class EscalationPath(val path: List<String>) {
    fun describe(): String = path.joinToString(" -> ")
}
