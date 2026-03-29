# Security Policy

If you find a vulnerability in `secretproxy`, please do not open a public issue first.

Report it privately by contacting the maintainer and include:

- affected version or commit
- impact and attack scenario
- reproduction steps
- suggested fix, if you have one

I will acknowledge the report, validate it, and coordinate a fix before public disclosure.

## Scope

This project is a local single-user proxy. Relevant reports include:

- secret leakage that bypasses masking expectations
- unmasking bugs that expose placeholders or secrets incorrectly
- request forwarding bugs that disclose sensitive content unexpectedly
- unsafe service or config behaviors with practical impact

Non-security bugs and feature requests should go through normal GitHub issues.
