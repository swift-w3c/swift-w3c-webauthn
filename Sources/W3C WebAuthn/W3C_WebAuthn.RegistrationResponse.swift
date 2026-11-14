public import RFC_8259

extension W3C_WebAuthn {

    /// A registration as the browser writes it with `PublicKeyCredential.toJSON()` (`RegistrationResponseJSON`,
    /// section 5.1.3).
    public struct RegistrationResponse: Sendable, Hashable {

        /// `rawId`: the credential ID.
        public let id: [UInt8]

        /// `response.clientDataJSON`.
        public let clientDataJSON: [UInt8]

        /// `response.attestationObject`.
        public let attestationObject: [UInt8]

        /// `response.transports`, when the browser gave them.
        public let transports: [Transport]

        /// The response from its JSON value.
        public init(_ value: RFC_8259.Value) throws(W3C_WebAuthn.Error) {
            guard value["type"]?.string == "public-key",
                let id = value["rawId"]?.string.flatMap(W3C_WebAuthn.Base64URL.decode),
                let response = value["response"],
                let clientDataJSON = response["clientDataJSON"]?.string.flatMap(W3C_WebAuthn.Base64URL.decode),
                let attestationObject = response["attestationObject"]?.string.flatMap(W3C_WebAuthn.Base64URL.decode)
            else { throw .response }
            self.id = id
            self.clientDataJSON = clientDataJSON
            self.attestationObject = attestationObject
            self.transports = (response["transports"]?.array.map(Array.init) ?? []).compactMap { item in
                item.string.map(Transport.init(rawValue:))
            }
        }
    }
}
