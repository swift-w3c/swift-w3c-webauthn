extension W3C_WebAuthn {

    /// `AuthenticatorTransport` (section 5.8.4): how the browser may reach an authenticator. Open, so values a
    /// browser adds later are kept.
    public struct Transport: RawRepresentable, Sendable, Hashable {

        public let rawValue: String

        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        public static let usb = Self(rawValue: "usb")
        public static let nfc = Self(rawValue: "nfc")
        public static let ble = Self(rawValue: "ble")
        public static let smartCard = Self(rawValue: "smart-card")
        public static let hybrid = Self(rawValue: "hybrid")
        public static let `internal` = Self(rawValue: "internal")
    }
}
