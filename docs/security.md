# Security model

The trust boundary contains local authenticated operators, the application, PostgreSQL, and configured SMTP. Customer cloud systems are outside it. Cookie authentication uses ASP.NET Core Identity hashing, strict SameSite/HttpOnly cookies, lockout, and role policies. APIs are rate-limited and return Problem Details without production stack traces.

RSA keys and certificates are generated in memory. The password-protected PFX is returned only in the generation response; RSA and certificate objects are disposed and only metadata is persisted. Passwords, PFX bytes, and private keys must never enter logs, audit metadata, email, or backups. Generated downloads should be stored immediately in an approved secret store by the operator.

Deployment confirmation records an operator assertion only. Decommissioning is a lifecycle label, not revocation. This application is not a CA and provides no CRL or OCSP.
