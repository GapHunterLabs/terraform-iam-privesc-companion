# Privacy Policy — Terraform IAM Privesc Companion

**Effective date:** 2026-10-06

Terraform IAM Privesc Companion is a Gap Hunter Labs plugin for IntelliJ Platform IDEs.

## What this plugin collects

**Nothing.** Terraform IAM Privesc Companion does not collect, transmit, or sell any data: no source
code, no file contents, no usage analytics, no telemetry, no crash reports,
no personally identifiable information.

## What it keeps on your machine

To decide when to show its one-time rating prompt, the plugin keeps two values
in the IDE's own settings on your computer: whether you have answered the
prompt, and a list of up to 500 findings it has already counted. Until the
next release, each entry in that list is the file path and line of a finding,
sometimes with its message. From the next release on, each entry is a one-way
fingerprint that cannot be turned back into a path, and the old list is
deleted. None of this is ever sent anywhere.

## Network access

**None.** Terraform IAM Privesc Companion makes no network calls. Every check runs inside the IDE, on
the files of the open project.

After a number of distinct findings, the plugin can show one notification
asking for a Marketplace review. Its **Rate on Marketplace** button opens the
plugin's JetBrains Marketplace page in the default browser, only when
clicked; the plugin itself sends nothing.

## Data stored on your machine

To decide when to show that notification, the plugin keeps, in the IDE's
own local settings, a capped list of keys for findings it has already
counted (a file path and line number) and whether the notification was
answered. None of it leaves the machine.

## Third parties

None. Terraform IAM Privesc Companion bundles no third-party SDKs or analytics libraries; it runs on
the IntelliJ Platform APIs only.

## Changes to this policy

If this changes, this file will be updated and the change noted in
[CHANGELOG.md](CHANGELOG.md).

## Contact

Questions about this policy: **gaphunterlabs@gmail.com**
