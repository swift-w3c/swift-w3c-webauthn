internal import RFC_8259
public import W3C

extension W3C.WebAuthn {

    /// The options of an authentication (`PublicKeyCredentialRequestOptions`, section 5.5).
    ///
    /// With no allowed credentials the browser offers the user's discoverable credentials for the RP ID, which
    /// is what the autofill prompt (conditional mediation) uses.
    public struct RequestOptions: Sendable, Hashable {

        public let relyingParty: RelyingParty

        /// The challenge: at least 16 random bytes, used once.
        public let challenge: [UInt8]

        /// How long the browser waits, in milliseconds.
        public let timeout: Int

        /// The credentials that may answer; empty for discoverable credentials.
        public let allowCredentials: [CredentialDescriptor]

        public init(
            relyingParty: RelyingParty,
            challenge: [UInt8],
            timeout: Int = 300_000,
            allowCredentials: [CredentialDescriptor] = []
        ) {
            precondition(challenge.count >= 16, "a challenge is at least 16 bytes")
            self.relyingParty = relyingParty
            self.challenge = challenge
            self.timeout = timeout
            self.allowCredentials = allowCredentials
        }
    }
}

extension W3C.WebAuthn.RequestOptions {

    /// The options as `PublicKeyCredentialRequestOptionsJSON` (section 5.1.6), for the browser's
    /// `PublicKeyCredential.parseRequestOptionsFromJSON`.
    public var json: [UInt8] {
        let options: [(key: String, value: RFC_8259.Value)] = [
            ("challenge", .string(W3C.WebAuthn.Base64URL.encode(challenge))),
            ("timeout", .number(RFC_8259.Number(timeout))),
            ("rpId", .string(relyingParty.id)),
            ("allowCredentials", .array(RFC_8259.Array(allowCredentials.map(\.json)))),
            ("userVerification", .string(relyingParty.userVerification.rawValue)),
        ]
        return RFC_8259.Encode.encode(.object(RFC_8259.Object(options)))
    }
}
