import RFC_8259
import Testing
import W3C_WebAuthn

@Suite
struct `Response Tests` {

    static func base64URL(_ bytes: [UInt8]) -> String {
        let alphabet: [Unicode.Scalar] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".unicodeScalars)
        var text = ""
        var index = 0
        while index < bytes.count {
            let chunk: [UInt8] = Array(bytes[index..<min(index + 3, bytes.count)])
            var value = 0
            for (offset, byte) in chunk.enumerated() {
                value |= Int(byte) << (16 - 8 * offset)
            }
            for position in 0...chunk.count {
                text.unicodeScalars.append(alphabet[(value >> (18 - 6 * position)) & 0x3f])
            }
            index += 3
        }
        return text
    }

    @Test
    func `a registration in the browser's JSON form is read`() throws {
        let vector = Example.noAttestation
        let id = Self.base64URL(hex(vector.credentialID))
        let response: RFC_8259.Value = [
            "id": .string(id),
            "rawId": .string(id),
            "type": "public-key",
            "response": [
                "clientDataJSON": .string(Self.base64URL(hex(vector.registrationClientDataJSON))),
                "attestationObject": .string(Self.base64URL(hex(vector.attestationObject))),
                "transports": ["internal", "hybrid"],
            ],
            "clientExtensionResults": [:],
        ]
        let read = try W3C.WebAuthn.RegistrationResponse(response)
        #expect(read.id == hex(vector.credentialID))
        #expect(read.attestationObject == hex(vector.attestationObject))
        #expect(read.transports == [.internal, .hybrid])
    }

    @Test
    func `an assertion in the browser's JSON form is read, with or without a user handle`() throws {
        let vector = Example.noAttestation
        let id = Self.base64URL(hex(vector.credentialID))
        let body: RFC_8259.Value = [
            "clientDataJSON": .string(Self.base64URL(hex(vector.authenticationClientDataJSON))),
            "authenticatorData": .string(Self.base64URL(hex(vector.authenticatorData))),
            "signature": .string(Self.base64URL(hex(vector.signature))),
            "userHandle": nil,
        ]
        let response: RFC_8259.Value = ["id": .string(id), "rawId": .string(id), "type": "public-key", "response": body]
        let read = try W3C.WebAuthn.AuthenticationResponse(response)
        #expect(read.signature == hex(vector.signature))
        #expect(read.userHandle == nil)
        #expect(throws: W3C.WebAuthn.Error.response) {
            try W3C.WebAuthn.AuthenticationResponse(["id": .string(id), "type": "public-key"])
        }
    }
}
