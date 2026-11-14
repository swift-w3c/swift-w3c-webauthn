# swift-w3c-webauthn

Use this package on a relying party's server to offer passkeys: write the options the browser needs, and verify what it sends back, for registration and for sign-in (W3C Web Authentication Level 3). Send `W3C_WebAuthn.CreationOptions.json` or `W3C_WebAuthn.RequestOptions.json` to the page, which passes them to `PublicKeyCredential.parseCreationOptionsFromJSON` or `parseRequestOptionsFromJSON`. Verify the response with `W3C_WebAuthn.Registration.verify` and store the `W3C_WebAuthn.Credential` it returns; verify a sign-in with `W3C_WebAuthn.Assertion.verify` and store the credential it returns in place of the old one. Describe the relying party once, in `W3C_WebAuthn.RelyingParty`.

## Laws

- Every ES256 example of section 16 registers and signs in: no attestation, self attestation, a cross-origin frame, a top origin, and a 1023-byte credential ID.
- ES256 signatures are read as DER `Ecdsa-Sig-Value` and agree with all 484 Wycheproof `ecdsa_secp256r1_sha256` vectors, which include every malformed DER encoding they test.
- Each ceremony checks, in the order of sections 7.1 and 7.2: the client data's type, the challenge, an origin from the relying party's list, the cross-origin context, the RP ID hash, user presence, user verification when required, a backed-up flag only with backup eligibility, the credential's algorithm, and the signature. Each failure throws the `W3C_WebAuthn.Error` that names it.
- Only ES256 credentials are accepted so far; a key of another algorithm is refused at registration with `.algorithm`.
- Attestation `none` and `packed` self attestation are verified. Any other format, and `packed` with a certificate chain, is refused with `.attestationFormat`, since no trust anchors are configured. The options always ask for attestation `none`.
- In a sign-in, backup eligibility must equal the registered credential's, and when either counter is not zero the new counter must be greater than the stored one; otherwise `.counter` is thrown, so a possibly cloned credential can be flagged.
- Challenges are compared in constant time; the relying party issues each one once, stores it, and passes it in. Finding the credential by its ID, checking the user handle, and refusing a credential ID registered before are the relying party's.
- The options ask for a discoverable credential (`residentKey` required) and the relying party's user verification. A user handle is 1 to 64 bytes and a challenge at least 16; anything else is a programming error.
- No I/O: every input is bytes, every output a value.
