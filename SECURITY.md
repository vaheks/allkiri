# Security policy

This library handles authentication tokens, certificates, revocation data and
signature creation. Bugs here can let a forged login through or produce a
signature that validators reject or, worse, accept when they should not.

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's
private vulnerability reporting on this repository ("Security" tab, "Report a
vulnerability"). You will get an acknowledgement within a few days.

Please include a minimal reproduction: the container or token, the
configuration used, and what you expected. Test-environment material only;
never send a container signed with a real person's certificate.

## Scope

In scope: anything in `src/` and `assets/`, and the demo application under
`examples/` insofar as it demonstrates unsafe use of the library.

Out of scope: the SK ID Solutions, RIA and Zetes services themselves, the
Web eID browser components, and the `web-eid/web-eid-authtoken-validation-php`
dependency. Report those to their maintainers.

## Supported versions

Until 1.0 only the `main` branch is supported. After 1.0 the latest minor
release is supported.
