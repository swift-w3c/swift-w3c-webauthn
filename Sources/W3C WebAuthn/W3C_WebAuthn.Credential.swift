extension W3C_WebAuthn {

    /// A registered credential: what a relying party stores after a registration and passes back to verify an
    /// assertion (section 7.1, step 26).
    public struct Credential: Sendable, Hashable {

        /// The credential ID, by which the browser names the credential in an assertion.
        public let id: [UInt8]

        /// The credential public key as a COSE key.
        public let publicKey: [UInt8]

        /// The signature counter last seen.
        public var signCount: UInt32

        /// The AAGUID of the authenticator model that made it.
        public let aaguid: [UInt8]

        /// Whether the credential may be backed up (BE); fixed for the credential's life.
        public let backupEligible: Bool

        /// Whether the credential was backed up at the last ceremony (BS).
        public var backedUp: Bool

        /// Whether the user was verified at the last ceremony (UV).
        public var userVerified: Bool

        /// The attestation statement format it was registered with.
        public let attestationFormat: String

        public init(
            id: [UInt8],
            publicKey: [UInt8],
            signCount: UInt32,
            aaguid: [UInt8],
            backupEligible: Bool,
            backedUp: Bool,
            userVerified: Bool,
            attestationFormat: String
        ) {
            self.id = id
            self.publicKey = publicKey
            self.signCount = signCount
            self.aaguid = aaguid
            self.backupEligible = backupEligible
            self.backedUp = backedUp
            self.userVerified = userVerified
            self.attestationFormat = attestationFormat
        }
    }
}
