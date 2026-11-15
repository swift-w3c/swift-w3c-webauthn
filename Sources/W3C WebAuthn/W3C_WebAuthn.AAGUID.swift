extension W3C_WebAuthn {

    /// The authenticator model's identifier (section 6.5.1): 16 bytes, all zero when the authenticator does not
    /// say which model it is.
    public struct AAGUID: Sendable, Hashable {

        /// The 16 bytes.
        public let bytes: [UInt8]

        /// An AAGUID from exactly 16 bytes.
        public init?(bytes: [UInt8]) {
            guard bytes.count == 16 else { return nil }
            self.bytes = bytes
        }

        /// An AAGUID from 32 hex digits, either case; dashes, as in the usual UUID form, are ignored.
        public init?(hex text: String) {
            let digits = Array(text.utf8.filter { $0 != UInt8(ascii: "-") })
            guard digits.count == 32 else { return nil }
            var bytes: [UInt8] = []
            bytes.reserveCapacity(16)
            var index = 0
            while index < 32 {
                guard let high = Self.value(digits[index]), let low = Self.value(digits[index + 1]) else { return nil }
                bytes.append(high << 4 | low)
                index += 2
            }
            self.bytes = bytes
        }

        /// The AAGUID of an authenticator that does not name its model.
        public static let zero = AAGUID(uncheckedBytes: [UInt8](repeating: 0, count: 16))

        /// Whether the authenticator left its model unnamed.
        public var isZero: Bool { bytes.allSatisfy { $0 == 0 } }

        /// The 32 lowercase hex digits, without dashes.
        public var hex: String {
            let digits = Array("0123456789abcdef".utf8)
            var text: [UInt8] = []
            text.reserveCapacity(32)
            for byte in bytes {
                text.append(digits[Int(byte >> 4)])
                text.append(digits[Int(byte & 0x0f)])
            }
            return String(decoding: text, as: UTF8.self)
        }

        init(uncheckedBytes bytes: [UInt8]) {
            self.bytes = bytes
        }

        static func value(_ digit: UInt8) -> UInt8? {
            switch digit {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): digit - UInt8(ascii: "A") + 10
            default: nil
            }
        }
    }
}
