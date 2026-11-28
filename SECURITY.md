# Security Policy

## Scope

- **Classic** (all 4 languages) is a documented weak deterrent, not a security boundary. Its reversibility is by design, not a bug. Don't report it.
- **PRO** (hardened + native-logic, all 4 languages): anything that defeats the external-key boundary without the key is in scope.
- **Build tools** (all 4 CLIs/APIs): path traversal, code/command injection via crafted input, insecure temp files, and similar are in scope.

Covers all four ports: `/` (Python), `js/`, `dotnet/`, `java/`.

## Supported Versions

Single rolling `main` branch. No older releases are maintained separately.

## Reporting a Vulnerability

Do not open a public GitHub issue. Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/g0w6y/obsor/security).
2. Click **Report a vulnerability**.
3. Include affected language/tier/file, a reproduction case, and impact.

## Response Time

This project is maintained by one person. Reports are acknowledged within 7 days.

## Credit

Reporters are credited by name/handle in the published advisory and the fixing commit, unless you ask to stay anonymous.
