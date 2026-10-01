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

Every alpha before `0.7.0-alpha.1` carries five known flaws in how trust,
signing certificates, revocation responders and timestamp authorities are
checked. They are listed under Security in the changelog entry for
`0.7.0-alpha.1`. Every alpha before `0.8.0-alpha.1` also lets anyone who can
reach an ID card sign-in make the server request an address of their choosing
([GHSA-g8p9-743j-jg7r](https://github.com/vaheks/allkiri/security/advisories/GHSA-g8p9-743j-jg7r)),
and every alpha before `0.9.0-alpha.1` can be made to spend minutes on one
small container sent for validation, to throw where it promised a report, or
to read a ZIP differently from a streaming reader
([GHSA-wp7r-h56v-f8p4](https://github.com/vaheks/allkiri/security/advisories/GHSA-wp7r-h56v-f8p4)).
None of them will be fixed on an older tag, because none of those tags is
supported: upgrade instead.

Tags are not removed once published, so an old one stays installable. Take the
newest release rather than pinning to an exact alpha.
