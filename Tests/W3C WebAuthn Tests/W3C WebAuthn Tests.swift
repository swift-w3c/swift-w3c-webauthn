import Testing
import W3C_WebAuthn

@Suite
struct `W3C WebAuthn Tests` {

    /// The relying party of section 16, accepting every example's context.
    static let examples = W3C_WebAuthn.RelyingParty(
        id: "example.org",
        name: "Example",
        origins: ["https://example.org"],
        userVerification: .preferred,
        allowsCrossOrigin: true,
        topOrigins: ["https://example.com"]
    )

    static func register(
        _ vector: Example.Vector,
        relyingParty: W3C_WebAuthn.RelyingParty = examples
    ) throws(W3C_WebAuthn.Error) -> W3C_WebAuthn.Credential {
        try W3C_WebAuthn.Registration.verify(
            clientDataJSON: hex(vector.registrationClientDataJSON),
            attestationObject: hex(vector.attestationObject),
            challenge: hex(vector.registrationChallenge),
            relyingParty: relyingParty
        )
    }

    static func authenticate(
        _ vector: Example.Vector,
        credential: W3C_WebAuthn.Credential,
        relyingParty: W3C_WebAuthn.RelyingParty = examples,
        signature: [UInt8]? = nil
    ) throws(W3C_WebAuthn.Error) -> W3C_WebAuthn.Credential {
        try W3C_WebAuthn.Assertion.verify(
            clientDataJSON: hex(vector.authenticationClientDataJSON),
            authenticatorData: hex(vector.authenticatorData),
            signature: signature ?? hex(vector.signature),
            challenge: hex(vector.authenticationChallenge),
            relyingParty: relyingParty,
            credential: credential
        )
    }

    @Test(arguments: Example.all)
    func `section 16 registrations verify`(_ vector: Example.Vector) throws {
        let credential = try Self.register(vector)
        #expect(credential.id == hex(vector.credentialID))
        #expect(credential.signCount == 0)
        let publicKey = try W3C_WebAuthn.PublicKey(cose: credential.publicKey)
        #expect(publicKey.algorithm == .es256)
    }

    @Test(arguments: Example.all)
    func `section 16 assertions verify with the registered credential`(_ vector: Example.Vector) throws {
        let credential = try Self.register(vector)
        let updated = try Self.authenticate(vector, credential: credential)
        #expect(updated.id == credential.id)
        #expect(updated.signCount == 0)
    }

    @Test
    func `the flags of the no-attestation example are read`() throws {
        let object = try W3C_WebAuthn.AttestationObject(hex(Example.noAttestation.attestationObject))
        #expect(object.format == "none")
        #expect(object.authenticatorData.flags == [.userPresent, .backupEligible, .backedUp, .attestedCredentialData])
        #expect(object.authenticatorData.attestedCredentialData?.aaguid == W3C_WebAuthn.AAGUID(hex: "8446ccb9-ab1d-b374-750b-2367ff6f3a1f"))
        let credential = try Self.register(Example.noAttestation)
        #expect(credential.backupEligible)
        #expect(credential.backedUp)
        #expect(!credential.userVerified)
        #expect(credential.attestationFormat == "none")
    }

    @Test
    func `self attestation is verified`() throws {
        let credential = try Self.register(Example.selfAttestation)
        #expect(credential.attestationFormat == "packed")
        #expect(credential.userVerified)
    }

    @Test
    func `a credential ID of 1023 bytes is accepted`() throws {
        let credential = try Self.register(Example.longCredentialID)
        #expect(credential.id.count == 1023)
    }

    @Test
    func `user verification is enforced when required`() {
        let strict = W3C_WebAuthn.RelyingParty(id: "example.org", name: "Example", origins: ["https://example.org"])
        #expect(throws: W3C_WebAuthn.Error.userVerification) { try Self.register(Example.noAttestation, relyingParty: strict) }
        #expect(throws: Never.self) { try Self.register(Example.selfAttestation, relyingParty: strict) }
    }

    @Test
    func `the challenge, origin and RP ID must be the relying party's`() {
        let vector = Example.noAttestation
        #expect(throws: W3C_WebAuthn.Error.challenge) {
            try W3C_WebAuthn.Registration.verify(
                clientDataJSON: hex(vector.registrationClientDataJSON),
                attestationObject: hex(vector.attestationObject),
                challenge: hex(vector.authenticationChallenge),
                relyingParty: Self.examples
            )
        }
        let otherOrigin = W3C_WebAuthn.RelyingParty(
            id: "example.org",
            name: "Example",
            origins: ["https://login.example.org"],
            userVerification: .preferred
        )
        #expect(throws: W3C_WebAuthn.Error.origin("https://example.org")) {
            try Self.register(vector, relyingParty: otherOrigin)
        }
        let otherID = W3C_WebAuthn.RelyingParty(
            id: "example.com",
            name: "Example",
            origins: ["https://example.org"],
            userVerification: .preferred
        )
        #expect(throws: W3C_WebAuthn.Error.relyingPartyID) { try Self.register(vector, relyingParty: otherID) }
    }

    @Test
    func `cross-origin ceremonies are refused unless accepted`() {
        let sameOrigin = W3C_WebAuthn.RelyingParty(
            id: "example.org",
            name: "Example",
            origins: ["https://example.org"],
            userVerification: .preferred
        )
        #expect(throws: W3C_WebAuthn.Error.crossOrigin) { try Self.register(Example.crossOrigin, relyingParty: sameOrigin) }
        let noTopOrigins = W3C_WebAuthn.RelyingParty(
            id: "example.org",
            name: "Example",
            origins: ["https://example.org"],
            userVerification: .preferred,
            allowsCrossOrigin: true
        )
        #expect(throws: Never.self) { try Self.register(Example.crossOrigin, relyingParty: noTopOrigins) }
        #expect(throws: W3C_WebAuthn.Error.crossOrigin) { try Self.register(Example.topOrigin, relyingParty: noTopOrigins) }
    }

    @Test
    func `a registration's client data is not an assertion's`() throws {
        let vector = Example.noAttestation
        let credential = try Self.register(vector)
        #expect(throws: W3C_WebAuthn.Error.type("webauthn.create")) {
            try W3C_WebAuthn.Assertion.verify(
                clientDataJSON: hex(vector.registrationClientDataJSON),
                authenticatorData: hex(vector.authenticatorData),
                signature: hex(vector.signature),
                challenge: hex(vector.registrationChallenge),
                relyingParty: Self.examples,
                credential: credential
            )
        }
    }

    @Test
    func `a signature that does not verify is refused`() throws {
        let vector = Example.noAttestation
        let credential = try Self.register(vector)
        var signature = hex(vector.signature)
        signature[signature.count - 1] ^= 0x01
        #expect(throws: W3C_WebAuthn.Error.signature) {
            try Self.authenticate(vector, credential: credential, signature: signature)
        }
        let other = try Self.register(Example.selfAttestation)
        #expect(throws: W3C_WebAuthn.Error.signature) {
            try Self.authenticate(
                vector,
                credential: W3C_WebAuthn.Credential(
                    id: credential.id,
                    publicKey: other.publicKey,
                    signCount: 0,
                    aaguid: credential.aaguid,
                    backupEligible: true,
                    backedUp: true,
                    userVerified: false,
                    attestationFormat: "none"
                )
            )
        }
    }

    @Test
    func `a counter that does not increase is refused`() throws {
        let vector = Example.noAttestation
        var credential = try Self.register(vector)
        credential.signCount = 5
        #expect(throws: W3C_WebAuthn.Error.counter(stored: 5, received: 0)) {
            try Self.authenticate(vector, credential: credential)
        }
    }

    @Test
    func `backup eligibility may not change`() throws {
        let vector = Example.noAttestation
        let credential = try Self.register(vector)
        let changed = W3C_WebAuthn.Credential(
            id: credential.id,
            publicKey: credential.publicKey,
            signCount: 0,
            aaguid: credential.aaguid,
            backupEligible: false,
            backedUp: false,
            userVerified: false,
            attestationFormat: "none"
        )
        #expect(throws: W3C_WebAuthn.Error.backupState) { try Self.authenticate(vector, credential: changed) }
    }

    @Test
    func `authenticator data with bytes after it, or too short, is refused`() throws {
        let data = hex(Example.noAttestation.authenticatorData)
        #expect(throws: Never.self) { try W3C_WebAuthn.AuthenticatorData(data) }
        #expect(throws: W3C_WebAuthn.Error.authenticatorData) { try W3C_WebAuthn.AuthenticatorData(data + [0]) }
        #expect(throws: W3C_WebAuthn.Error.authenticatorData) { try W3C_WebAuthn.AuthenticatorData(Array(data.dropLast())) }
    }

    @Test(arguments: Wycheproof.tests)
    func `Wycheproof DER signatures verify as ES256`(_ test: Wycheproof.Test) throws {
        let key = W3C_WebAuthn.PublicKey.es256(try FIPS_186_5.ECDSA.P256.PublicKey(x: hex(test.x), y: hex(test.y)))
        #expect(key.isValidSignature(hex(test.signature), for: hex(test.message)) == test.valid)
    }

    @Test
    func `creation options are written as the browser's JSON form`() {
        let relyingParty = W3C_WebAuthn.RelyingParty(id: "example.org", name: "Example", origins: ["https://example.org"])
        let options = W3C_WebAuthn.CreationOptions(
            relyingParty: relyingParty,
            userID: [1, 2, 3],
            userName: "ada@example.org",
            userDisplayName: "Ada",
            challenge: Array(0..<16),
            excludeCredentials: [.init(id: [1, 2, 3], transports: [.internal, .hybrid])]
        )
        let expected =
            #"{"rp":{"id":"example.org","name":"Example"},"user":{"id":"AQID","name":"ada@example.org","#
            + #""displayName":"Ada"},"challenge":"AAECAwQFBgcICQoLDA0ODw","pubKeyCredParams":[{"type":"public-key","#
            + #""alg":-7}],"timeout":300000,"excludeCredentials":[{"type":"public-key","id":"AQID","transports":"#
            + #"["internal","hybrid"]}],"authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"#
            + #""userVerification":"required"},"attestation":"none"}"#
        #expect(String(decoding: options.json, as: UTF8.self) == expected)
    }

    @Test
    func `request options are written as the browser's JSON form`() {
        let relyingParty = W3C_WebAuthn.RelyingParty(id: "example.org", name: "Example", origins: ["https://example.org"])
        let options = W3C_WebAuthn.RequestOptions(relyingParty: relyingParty, challenge: Array(0..<16))
        let expected =
            #"{"challenge":"AAECAwQFBgcICQoLDA0ODw","timeout":300000,"rpId":"example.org","#
            + #""allowCredentials":[],"userVerification":"required"}"#
        #expect(String(decoding: options.json, as: UTF8.self) == expected)
    }
}

@Suite
struct `AAGUID Tests` {
    @Test
    func `an AAGUID is sixteen bytes, read from hex in either case with or without dashes, and written back in lowercase`() {
        let aaguid = W3C_WebAuthn.AAGUID(hex: "FBFC3007-154E-4ECC-8C0B-6E020557D7BD")
        #expect(aaguid?.hex == "fbfc3007154e4ecc8c0b6e020557d7bd")
        #expect(aaguid == W3C_WebAuthn.AAGUID(hex: "fbfc3007154e4ecc8c0b6e020557d7bd"))
        #expect(W3C_WebAuthn.AAGUID(hex: "fbfc3007") == nil)
        #expect(W3C_WebAuthn.AAGUID(hex: "zz" + String(repeating: "0", count: 30)) == nil)
        #expect(W3C_WebAuthn.AAGUID(bytes: [1, 2, 3]) == nil)
        #expect(W3C_WebAuthn.AAGUID.zero.isZero)
        #expect(aaguid?.isZero == false)
        #expect(W3C_WebAuthn.AAGUID(bytes: aaguid?.bytes ?? []) == aaguid)
    }
}
