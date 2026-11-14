extension W3C_WebAuthn {

    /// The flags byte of authenticator data (section 6.1).
    public struct Flags: OptionSet, Sendable, Hashable {

        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// UP: the user was present.
        public static let userPresent = Flags(rawValue: 0x01)

        /// UV: the user was verified, by biometrics or a PIN.
        public static let userVerified = Flags(rawValue: 0x04)

        /// BE: the credential may be backed up, synced to other devices.
        public static let backupEligible = Flags(rawValue: 0x08)

        /// BS: the credential is backed up now.
        public static let backedUp = Flags(rawValue: 0x10)

        /// AT: attested credential data follows.
        public static let attestedCredentialData = Flags(rawValue: 0x40)

        /// ED: extension data follows.
        public static let extensionData = Flags(rawValue: 0x80)
    }
}
