# Security Policy

## Scope

This policy covers all four ports: `/` (Python), `js/`, `dotnet/`, and `java/`. Classic is a documented weak deterrent in every language, not a security boundary, so its reversibility is by design and not something to report. PRO's hardened and native-logic tiers make a real external-key-boundary claim in all four languages, so anything that defeats that boundary without the key is in scope. The build tools themselves (the CLIs and library APIs in all four ports) are also in scope for issues like path traversal, code or command injection via crafted input, and insecure temp file handling.

## Supported Versions

This project has a single rolling `main` branch, and no older releases are maintained separately.

## Reporting a Vulnerability

Do not open a public GitHub issue. Use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/g0w6y/obsor/security).
2. Click **Report a vulnerability**.
3. Include affected language/tier/file, a reproduction case, and impact.

## Response Time

This project is maintained by one person. Reports are acknowledged within 7 days.

## Credit

Reporters are credited by name/handle in the published advisory and the fixing commit, unless you ask to stay anonymous.
