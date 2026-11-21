public import W3C

extension W3C.WebAuthn {

    /// Attested credential data (section 6.5.2): the authenticator model, the new credential's ID and its
    /// public key.
    public struct AttestedCredentialData: Sendable, Hashable {

        /// The AAGUID of the authenticator model; ``AAGUID/zero`` when the authenticator does not say.
        public let aaguid: AAGUID

        /// The credential ID.
        public let credentialID: [UInt8]

        /// The credential public key, a COSE key.
        public let publicKey: RFC_9052.Key

        /// The credential public key exactly as encoded, for storing.
        public let publicKeyBytes: [UInt8]
    }
}
