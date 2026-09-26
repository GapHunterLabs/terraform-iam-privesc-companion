<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Terraform IAM Privesc Companion Changelog

## [Unreleased]

## [0.1.1]

### Fixed

- Review/star CTA now links to this plugin's own Marketplace
  reviews page instead of the vendor's generic plugin list.

## [0.1.0]

### Added

- Whole-project AssumeRole trust-chain graph across every `.tf` file,
  flagging an `aws_iam_role` that can reach an admin-equivalent role
  via a real BFS (cycle-safe, unbounded depth).
- Admin-equivalent detection via managed-policy attachment
  (`AdministratorAccess`), a referenced `aws_iam_policy` full-wildcard
  document, or an inline `aws_iam_role_policy` of the same shape.

[Unreleased]: https://github.com/GapHunterLabs/terraform-iam-privesc-companion/compare/0.1.1...HEAD
[0.1.1]: https://github.com/GapHunterLabs/terraform-iam-privesc-companion/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/GapHunterLabs/terraform-iam-privesc-companion/commits/0.1.0
