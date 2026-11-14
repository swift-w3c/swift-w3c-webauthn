extension W3C_WebAuthn {

    /// Authenticator data (section 6.1): the RP ID hash, the flags, the signature counter, and, when the flags
    /// say so, attested credential data and extensions.
    public struct AuthenticatorData: Sendable, Hashable {

        /// The bytes exactly as received; an assertion's signature covers them.
        public let bytes: [UInt8]

        /// `rpIdHash`: the SHA-256 of the RP ID the authenticator scoped the credential to.
        public let relyingPartyIDHash: [UInt8]

        public let flags: Flags

        /// `signCount`: zero when the authenticator keeps no counter.
        public let signCount: UInt32

        /// Present when the AT flag is set: in a registration's authenticator data.
        public let attestedCredentialData: AttestedCredentialData?

        /// The extension outputs, a CBOR map, present when the ED flag is set.
        public let extensions: RFC_8949.Value?

        public init(_ bytes: [UInt8]) throws(W3C_WebAuthn.Error) {
            guard bytes.count >= 37 else { throw .authenticatorData }
            let flags = Flags(rawValue: bytes[32])
            var count: UInt32 = 0
            for byte in bytes[33..<37] {
                count = count << 8 | UInt32(byte)
            }
            var position = 37

            var attested: AttestedCredentialData? = nil
            if flags.contains(.attestedCredentialData) {
                guard bytes.count - position >= 18 else { throw .authenticatorData }
                let aaguid = Array(bytes[position..<(position + 16)])
                let length = Int(bytes[position + 16]) << 8 | Int(bytes[position + 17])
                position += 18
                guard bytes.count - position >= length else { throw .authenticatorData }
                let credentialID = Array(bytes[position..<(position + length)])
                position += length
                var decoder = RFC_8949.Decoder(bytes, position: position)
                let key: RFC_9052.Key
                do {
                    key = try RFC_9052.Key(try decoder.decode())
                } catch {
                    throw .authenticatorData
                }
                attested = AttestedCredentialData(
                    aaguid: aaguid,
                    credentialID: credentialID,
                    publicKey: key,
                    publicKeyBytes: Array(bytes[position..<decoder.position])
                )
                position = decoder.position
            }

            var extensions: RFC_8949.Value? = nil
            if flags.contains(.extensionData) {
                var decoder = RFC_8949.Decoder(bytes, position: position)
                guard let value = try? decoder.decode(), case .map = value else { throw .authenticatorData }
                extensions = value
                position = decoder.position
            }

            guard position == bytes.count else { throw .authenticatorData }
            self.bytes = bytes
            self.relyingPartyIDHash = Array(bytes[0..<32])
            self.flags = flags
            self.signCount = count
            self.attestedCredentialData = attested
            self.extensions = extensions
        }
    }
}

extension W3C_WebAuthn.AuthenticatorData {

    /// Steps 13 to 16 of section 7.1 and 15 to 18 of section 7.2: the RP ID hash, user presence, user
    /// verification when required, and a backup state that is possible.
    func verify(relyingParty: W3C_WebAuthn.RelyingParty) throws(W3C_WebAuthn.Error) {
        guard W3C_WebAuthn.constantTimeEqual(relyingPartyIDHash, relyingParty.idHash) else { throw .relyingPartyID }
        guard flags.contains(.userPresent) else { throw .userPresence }
        if relyingParty.userVerification == .required {
            guard flags.contains(.userVerified) else { throw .userVerification }
        }
        if flags.contains(.backedUp) {
            guard flags.contains(.backupEligible) else { throw .backupState }
        }
    }
}
