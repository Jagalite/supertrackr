# Anonymous key enrollment

Public trackers accept anonymous key holders when `--open-registration` is enabled.
There are no accounts, names, email addresses, or real-world identity checks.
An active registration binds a public key to an endpoint and a bearer session
credential. The endpoint is a hint, not proof of control of an IP address.

## Proof exchange

1. The client generates a random 32-byte nonce and requests a challenge for its
   X25519/WireGuard public key and endpoint.
2. The server generates an ephemeral X25519 key, random 24-byte box nonce,
   random 32-byte challenge ID and random 32-byte secret. NaCl box
   (`crypto_box` SalsaBox: X25519/XSalsa20-Poly1305) encrypts the secret for the
   client's key. The server returns the ID, ephemeral public key, nonce and
   ciphertext as hex. Non-contributory X25519 keys are rejected.
3. The client decrypts with its private key. It returns HMAC-SHA256 keyed by the
   decrypted secret, over `supertrackr/enrollment/v1\0` followed by five fields,
   each prefixed by its byte length as a big-endian u64: configured canonical
   tracker origin, public key bytes, Rust SocketAddr text, client nonce bytes,
   challenge ID bytes. The raw secret is never returned.
4. The server compares SHA-256 of the supplied HMAC against its stored expected
   digest, in constant time, checks the key, endpoint and 30-second deadline,
   then atomically consumes the challenge and admits the registration. It stores
   only the digest, key, endpoint and deadline with the pending ID.

The client uses its configured origin, not an origin supplied by the challenge.
The server requires `--public-origin https://tracker.example/` for HTTPS; loopback
`--lab-http` defaults to its listen address. A reverse proxy must use its externally
visible origin in this setting. Root origins only; HTTPS certificate validation
protects deployed control traffic. Loopback HTTP is an explicit lab exception.
The origin binding prevents a different tracker from simply forwarding a challenge
and using the client's response against the intended tracker.

## Ownership and lifetime

A challenge does not reserve a registration slot or identity. Multiple challenges
for a key may coexist, but only the first successful enrollment can create its
record. All other completions conflict without replacing its token or endpoint.
A consumed proof cannot be replayed, including after the registration expires.
Existing-token refresh remains one request and can update the endpoint; the token
is a bearer authorization credential and must be protected.

Pending challenges have a separate 4,096-entry bound and an expiry index; cleanup
removes at most 64 expired challenges per pass. All state is RAM-only. Restart
clears challenges and registrations. After lease expiry and cleanup, enrollment
requires a fresh proof of the same private key. Key rotation, identity transfer,
and account recovery are not implemented. Losing the key means losing that identity.
The internal synchronous Registry admission primitive is trusted; HTTP enrollment
reaches it only after proof validation. Internal state-cost benchmarks bypass the
network admission protocol and do not measure its cost.

## Scope and measurement

These are established cryptographic primitives in a new prototype protocol, not
an independently audited authentication protocol. Anonymous means account-free,
not untraceable: peers and the tracker still see network metadata. Proof of key
control does not prevent creating thousands of valid keys. The pending bound is
not a rate limiter or a complete defense against CPU, queue, or Sybil abuse.

Both bundled clients use the proof exchange. The load generator's `register` mode
measures challenge plus completion as one workflow; its rate is registrations per
second, requiring two HTTP requests on success. Service latency includes challenge
cryptography. Reported response bytes count the final response only. Historical
single-request registration benchmarks are not comparable. Other workload setup
also uses proof-bearing enrollment. `--calibration-only` skips proof solely for
loopback HTTP response-shape fixtures; the server has no such bypass. Calibration
results are explicitly labeled and do not qualify enrollment performance.
