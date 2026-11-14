extension W3C_WebAuthn {

    /// What a relying party accepts: its RP ID, its origins, how strictly it asks for user verification, and
    /// the public key algorithms it supports.
    public struct RelyingParty: Sendable, Hashable {

        /// The RP ID, a registrable domain such as `example.org` (section 5.1.2). Credentials are scoped to it,
        /// so one credential works on every origin under it that the relying party lists.
        public let id: String

        /// The human-palatable name shown during registration.
        public let name: String

        /// The exact origins, such as `https://example.org`, from which ceremonies are accepted.
        public let origins: Set<String>

        /// Whether user verification is required, preferred or discouraged (section 5.8.6).
        public let userVerification: UserVerification

        /// The algorithms a credential's public key may use, in order of preference.
        public let algorithms: [RFC_9053.Algorithm]

        /// Whether a ceremony run inside a cross-origin frame is accepted.
        public let allowsCrossOrigin: Bool

        /// The top-level origins under which a cross-origin ceremony is accepted.
        public let topOrigins: Set<String>

        public init(
            id: String,
            name: String,
            origins: Set<String>,
            userVerification: UserVerification = .required,
            algorithms: [RFC_9053.Algorithm] = [.es256],
            allowsCrossOrigin: Bool = false,
            topOrigins: Set<String> = []
        ) {
            self.id = id
            self.name = name
            self.origins = origins
            self.userVerification = userVerification
            self.algorithms = algorithms
            self.allowsCrossOrigin = allowsCrossOrigin
            self.topOrigins = topOrigins
        }

        /// `rpIdHash`: the SHA-256 of the UTF-8 RP ID.
        public var idHash: [UInt8] { W3C_WebAuthn.sha256(Array(id.utf8)) }
    }
}

extension W3C_WebAuthn.RelyingParty {

    /// `UserVerificationRequirement` (section 5.8.6).
    public enum UserVerification: String, Sendable, Hashable {
        case required
        case preferred
        case discouraged
    }
}
