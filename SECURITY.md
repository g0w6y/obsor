# Security Policy

## Scope

obsor ships two tiers per language, and they have different security postures:

- **Classic** (all 4 languages) is documented, on purpose, as a weak
  deterrent — not a security boundary. "Classic obfuscation is reversible"
  is not a vulnerability; it's the stated design. Don't report it.
- **PRO** (hardened + native-logic, all 4 languages) makes a real
  external-key-boundary claim. A way to defeat that claim *without* the
  key — recover the payload, forge a valid artifact, bypass the
  authentication — is in scope.
- **The build tools themselves** (the CLIs and library APIs that take
  source/config and produce protected output) are in scope for anything
  that could compromise the machine running them: path traversal, code
  injection via a crafted input value, command injection into a spawned
  compiler, insecure temp-file handling, and similar. This project has
  already found and fixed exactly this class of bug via its own internal
  review (see commit history) — if you find another one, it's exactly the
  kind of report this policy wants.

Covers all four ports: `/` (Python), `js/`, `dotnet/`, `java/`.

## Supported Versions

This is a single rolling `main` branch with no maintained older releases.
Reports are evaluated against current `main`.

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Use GitHub's private vulnerability
reporting instead:

1. Go to the [Security tab](https://github.com/g0w6y/obsor/security).
2. Click **Report a vulnerability**.
3. Describe the issue: affected language/tier/file, a reproduction case,
   and the impact.

This opens a private draft security advisory visible only to you and the
maintainer — nothing is public until a fix ships and you both agree to
disclose.

## What to Expect

This is maintained by one person. There's no fixed SLA, but reports are
read and acknowledged as soon as possible, and a real, reproducible report
gets fixed — this project's track record is same-day fixes for everything
found so far, including through its own internal security review.

## Credit

Reporters are credited by name/handle in the published advisory and the
commit/changelog that fixes the issue, unless you ask to stay anonymous.
Say so in your report if you'd rather not be named.
