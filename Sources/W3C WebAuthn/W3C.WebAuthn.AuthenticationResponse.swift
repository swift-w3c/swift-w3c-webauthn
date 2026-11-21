public import RFC_8259
public import W3C

extension W3C.WebAuthn {

    /// An assertion as the browser writes it with `PublicKeyCredential.toJSON()` (`AuthenticationResponseJSON`,
    /// section 5.1.4).
    public struct AuthenticationResponse: Sendable, Hashable {

        /// `rawId`: the credential ID.
        public let id: [UInt8]

        /// `response.clientDataJSON`.
        public let clientDataJSON: [UInt8]

        /// `response.authenticatorData`.
        public let authenticatorData: [UInt8]

        /// `response.signature`.
        public let signature: [UInt8]

        /// `response.userHandle`, present for a discoverable credential.
        public let userHandle: [UInt8]?

        /// The response from its JSON value.
        public init(_ value: RFC_8259.Value) throws(W3C.WebAuthn.Error) {
            guard value["type"]?.string == "public-key",
                let id = value["rawId"]?.string.flatMap(W3C.WebAuthn.Base64URL.decode),
                let response = value["response"],
                let clientDataJSON = response["clientDataJSON"]?.string.flatMap(W3C.WebAuthn.Base64URL.decode),
                let authenticatorData = response["authenticatorData"]?.string.flatMap(W3C.WebAuthn.Base64URL.decode),
                let signature = response["signature"]?.string.flatMap(W3C.WebAuthn.Base64URL.decode)
            else { throw .response }
            let userHandle: [UInt8]?
            switch response["userHandle"] {
            case nil, .null?: userHandle = nil
            case .string(let text)?:
                guard let decoded = W3C.WebAuthn.Base64URL.decode(text) else { throw .response }
                userHandle = decoded
            default: throw .response
            }
            self.id = id
            self.clientDataJSON = clientDataJSON
            self.authenticatorData = authenticatorData
            self.signature = signature
            self.userHandle = userHandle
        }
    }
}
