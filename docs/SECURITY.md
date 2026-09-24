# Security Model

## Trust boundary

All user-supplied text, URLs and files are untrusted.

The application is a defensive investigation tool. It does not execute uploaded scripts, macros, binaries or embedded payloads.

## File controls

- 10 MB top-level upload limit
- extension/signature checks
- SHA-256 hashing
- bounded text extraction
- archive item-count limit
- archive expanded-size limit
- compression-ratio limit
- archive inspection time limit
- bounded email attachment analysis
- limited nested attachment depth
- static Office/PDF/HTML/SVG/script analysis
- possible polyglot indicator
- deceptive filename and bidirectional-control checks

## Network controls

Server-side redirect checks:

- HTTP(S) only
- maximum redirect count
- DNS resolution before contact
- every redirect hop revalidated
- private/loopback/link-local/reserved/multicast/unspecified targets blocked
- cloud metadata targets blocked
- redirects disabled in the HTTP client and handled explicitly
- strict timeouts
- environment proxy inheritance disabled for untrusted URL checks

The request connects to a validated IP address while preserving the original Host header and HTTPS SNI/certificate-hostname verification. This pins the connection target and prevents a second DNS lookup from substituting an internal address between validation and connect. Every redirect is checked again. This protection is covered by the SSRF regression suite; it is not a claim of complete network isolation.

This is not an active vulnerability scanner.

## External services

VirusTotal receives supported indicators such as domains, public IP addresses and SHA-256 hashes. Raw files are not uploaded by this workflow.

Gemini receives extracted content and structured evidence for synthesis. The model is instructed not to invent external reputation, identity or malware evidence.

## Persistence

V2 runtime persistence uses PostgreSQL. Supabase is the selected hosted provider.

- credentials are backend-only
- remote connections require TLS
- connection pooling is bounded
- one investigation write uses one database transaction
- evidence/findings/chain data are normalized into related tables
- SQLite exists only as an optional legacy migration source

## Failure behavior

- VirusTotal unavailable: local evidence remains available
- Gemini unavailable: deterministic evidence/findings remain available and the assessment becomes inconclusive/unavailable
- parser failure: successful partial analysis is preserved where possible
- QR failure: no claim is made that a QR does not exist
- SSRF block: traversal stops and the reason is recorded
- PostgreSQL write failure: the current investigation can still be returned with a persistence warning, but it will not be available in history

## Known limitations

Static indicators do not establish runtime compromise. Dynamic malware behavior, active exploitation, deep steganography, guaranteed sender attribution and exact sender physical location remain out of scope.

## Authentication and deployment caveats

The API validates each token using Supabase Auth. Global sign-out revokes refresh sessions, but already-issued access tokens may remain valid until their expiry; this API does not check auth.sessions on every request. Configure a short practical token lifetime. Browser 401 handling clears private state and requires sign-in.

Production readiness rejects database logins with superuser, BYPASSRLS, inheritance or application-table ownership. The public build validates its environment before compilation and scans emitted text for known secret values and credential patterns. This is defense in depth, not an exhaustive proof that no arbitrary secret could ever be committed.
