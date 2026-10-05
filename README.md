# Terraform IAM Privesc Companion

Flags a Terraform `aws_iam_role` that can reach an admin-equivalent
role through a real, whole-project AssumeRole trust chain.

## Why it exists

A single overly-permissive statement (this catalog's own Terraform IAM
Wildcard Companion) is one thing; a genuine multi-hop privilege-
escalation path across several roles is a different, more dangerous
finding entirely (CWE-269) -- the same technique Rhino Security Labs'
well-known IAM privilege-escalation research and the IAM-Vulnerable
benchmark document. PMapper builds that role-to-role graph by querying
a live, already-deployed AWS account (via `boto3`); Cloudsplaining can
also scan a single policy file offline and flags known escalation
methods in it, but it does not build a role-to-role graph. Both are CLI
tools -- neither is an IDE inspection that follows escalation paths
across roles in IaC source, before `terraform apply` ever runs. No
dedicated Marketplace plugin found for this exact angle.

## Why built this way

- **A real directed graph, not a bounded heuristic.** Every
  `resource "aws_iam_role"` in the project becomes a node; every
  `assume_role_policy` trust statement naming another in-project role
  as `Principal.AWS` (granting `sts:AssumeRole`) becomes an edge.
  Admin-equivalent roles are marked via managed-policy attachment
  (`AdministratorAccess`), a referenced `aws_iam_policy` document with
  a full wildcard statement, or an inline `aws_iam_role_policy` with
  the same shape.
- **BFS with cycle protection (a visited-set), never a fixed depth
  bound** -- the same correctness property a real graph-cycle
  algorithm needs, not an arbitrary "stop after N hops".
- **Not a JSON parser** -- `jsonencode({...})`'s argument is HCL
  map/list syntax, walked via brace/bracket balancing (same technique
  as Terraform IAM Wildcard Companion), never a real JSON parser.
- **Cached per-project**, invalidated on any PSI change -- rebuilding
  the whole-project graph on every keystroke across every `.tf` file
  would make on-the-fly highlighting unusably slow otherwise.

## v0.1 scope — stated honestly, not exhaustively

- Only resolves the direct HCL reference form
  (`aws_iam_role.NAME.arn`/`.id`/`.name`) for both a trust policy's
  `Principal.AWS` and a policy attachment's `role =` -- never a literal
  role name string, an interpolated local variable, or a cross-account
  ARN with no matching in-project resource (correctly not an edge:
  there's no in-project resource to escalate through anyway).
- The trust relationship alone is treated as the edge -- does not
  additionally cross-check that the trusting side also holds an
  identity-based `sts:AssumeRole` permission naming the target's ARN
  (same simplification PMapper's own graph model leans on).
- A single root module per scan (`module "x" { source = "./..." }` is
  not resolved/followed into a separate file tree).
- A project with more than 300 `.tf` files skips whole-project analysis
  entirely rather than risk hanging the IDE.
- Only the AssumeRole trust-chain primitive -- `iam:PassRole`,
  `iam:AttachRolePolicy`/`PutRolePolicy` self-grant,
  `iam:UpdateAssumeRolePolicy`, and `iam:CreatePolicyVersion` (four of
  the other well-documented escalation primitives) are explicitly out
  of scope for this version, left for a future extension.

## Usage

Open any `.tf` file declaring an `aws_iam_role` that has a real
AssumeRole path to an admin-equivalent role anywhere else in the
project -- the role's declaration line shows a warning naming the full
path.

## Support

- **Bugs and feature requests:** [GitHub Issues](https://github.com/GapHunterLabs/terraform-iam-privesc-companion/issues)
- **Questions, or custom rules for a team's codebase:** **gaphunterlabs@gmail.com**
- **Security vulnerabilities:** report privately as described in [SECURITY.md](SECURITY.md), not in a public issue.
- **Privacy and network behavior:** [PRIVACY.md](PRIVACY.md)

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
