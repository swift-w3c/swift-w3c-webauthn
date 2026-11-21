public import W3C

extension W3C.WebAuthn {

    /// The attestation object of a registration (section 6.5.4): the statement's format, the statement, and the
    /// authenticator data.
    public struct AttestationObject: Sendable, Hashable {

        /// `fmt`, such as `none` or `packed`.
        public let format: String

        /// `attStmt`, a CBOR map whose shape the format defines.
        public let statement: [RFC_8949.Pair]

        /// `authData`.
        public let authenticatorData: AuthenticatorData

        public init(_ bytes: [UInt8]) throws(W3C.WebAuthn.Error) {
            let value: RFC_8949.Value
            do {
                value = try RFC_8949.decode(bytes)
            } catch {
                throw .attestationObject
            }
            guard let format = value["fmt"]?.text,
                let statement = value["attStmt"]?.map,
                let authenticatorData = value["authData"]?.bytes
            else { throw .attestationObject }
            self.format = format
            self.statement = statement
            self.authenticatorData = try AuthenticatorData(authenticatorData)
        }
    }
}
