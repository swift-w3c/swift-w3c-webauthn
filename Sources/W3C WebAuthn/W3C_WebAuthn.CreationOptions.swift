internal import RFC_8259

extension W3C_WebAuthn {

    /// The options of a registration (`PublicKeyCredentialCreationOptions`, section 5.4), for a discoverable
    /// credential (a passkey) with no attestation.
    public struct CreationOptions: Sendable, Hashable {

        public let relyingParty: RelyingParty

        /// The user handle: random bytes per account, never personal data (section 14.6.1). At most 64 bytes.
        public let userID: [UInt8]

        /// The account's name, such as an email address, shown to tell accounts apart.
        public let userName: String

        /// The name shown for the account.
        public let userDisplayName: String

        /// The challenge: at least 16 random bytes, used once.
        public let challenge: [UInt8]

        /// How long the browser waits, in milliseconds.
        public let timeout: Int

        /// Credentials the user already has, so the same authenticator is not registered twice.
        public let excludeCredentials: [CredentialDescriptor]

        public init(
            relyingParty: RelyingParty,
            userID: [UInt8],
            userName: String,
            userDisplayName: String,
            challenge: [UInt8],
            timeout: Int = 300_000,
            excludeCredentials: [CredentialDescriptor] = []
        ) {
            precondition((1...64).contains(userID.count), "a user handle is 1 to 64 bytes")
            precondition(challenge.count >= 16, "a challenge is at least 16 bytes")
            self.relyingParty = relyingParty
            self.userID = userID
            self.userName = userName
            self.userDisplayName = userDisplayName
            self.challenge = challenge
            self.timeout = timeout
            self.excludeCredentials = excludeCredentials
        }
    }
}

extension W3C_WebAuthn.CreationOptions {

    /// The options as `PublicKeyCredentialCreationOptionsJSON` (section 5.1.5), for the browser's
    /// `PublicKeyCredential.parseCreationOptionsFromJSON`.
    public var json: [UInt8] {
        typealias Members = [(key: String, value: RFC_8259.Value)]
        let parameters: [RFC_8259.Value] = relyingParty.algorithms.map { algorithm in
            let alg = RFC_8259.Value.number(RFC_8259.Number(Int(algorithm.rawValue)))
            let members: Members = [("type", .string("public-key")), ("alg", alg)]
            return .object(RFC_8259.Object(members))
        }
        let rp: Members = [("id", .string(relyingParty.id)), ("name", .string(relyingParty.name))]
        let user: Members = [
            ("id", .string(W3C_WebAuthn.Base64URL.encode(userID))),
            ("name", .string(userName)),
            ("displayName", .string(userDisplayName)),
        ]
        let selection: Members = [
            ("residentKey", .string("required")),
            ("requireResidentKey", .bool(true)),
            ("userVerification", .string(relyingParty.userVerification.rawValue)),
        ]
        let options: Members = [
            ("rp", .object(RFC_8259.Object(rp))),
            ("user", .object(RFC_8259.Object(user))),
            ("challenge", .string(W3C_WebAuthn.Base64URL.encode(challenge))),
            ("pubKeyCredParams", .array(RFC_8259.Array(parameters))),
            ("timeout", .number(RFC_8259.Number(timeout))),
            ("excludeCredentials", .array(RFC_8259.Array(excludeCredentials.map(\.json)))),
            ("authenticatorSelection", .object(RFC_8259.Object(selection))),
            ("attestation", .string("none")),
        ]
        return RFC_8259.Encode.encode(.object(RFC_8259.Object(options)))
    }
}
