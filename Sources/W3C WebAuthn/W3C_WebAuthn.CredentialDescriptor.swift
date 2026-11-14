internal import RFC_8259

extension W3C_WebAuthn {

    /// `PublicKeyCredentialDescriptor` (section 5.8.3): a credential named in `excludeCredentials` or
    /// `allowCredentials`.
    public struct CredentialDescriptor: Sendable, Hashable {

        public let id: [UInt8]

        public let transports: [Transport]

        public init(id: [UInt8], transports: [Transport] = []) {
            self.id = id
            self.transports = transports
        }

        var json: RFC_8259.Value {
            var members: [(key: String, value: RFC_8259.Value)] = [
                ("type", .string("public-key")),
                ("id", .string(W3C_WebAuthn.Base64URL.encode(id))),
            ]
            if !transports.isEmpty {
                members.append(("transports", .array(RFC_8259.Array(transports.map { .string($0.rawValue) }))))
            }
            return .object(RFC_8259.Object(members))
        }
    }
}
