internal import Byte
internal import RFC_8259
public import W3C

extension W3C.WebAuthn {

    /// The client data the browser collected for a ceremony (`CollectedClientData`, section 5.8.1), read from
    /// `clientDataJSON`.
    ///
    /// Members this package does not know are ignored, as section 5.8.1.2 allows.
    public struct ClientData: Sendable, Hashable {

        /// The bytes of `clientDataJSON` exactly as received; their hash is what the authenticator signed.
        public let json: [UInt8]

        /// `webauthn.create` or `webauthn.get`.
        public let type: String

        /// The challenge, decoded from base64url.
        public let challenge: [UInt8]

        /// The origin of the document that called WebAuthn.
        public let origin: String

        /// Whether the call came from a frame whose origin differs from the top-level document's.
        public let crossOrigin: Bool

        /// The origin of the top-level document, present when it differs from `origin`.
        public let topOrigin: String?

        public init(json: [UInt8]) throws(W3C.WebAuthn.Error) {
            let value: RFC_8259.Value
            do {
                value = try RFC_8259.Decode.parse(json.map(Byte.init(_:)))
            } catch {
                throw .clientData
            }
            guard let type = value["type"]?.string,
                let encodedChallenge = value["challenge"]?.string,
                let challenge = W3C.WebAuthn.Base64URL.decode(encodedChallenge),
                let origin = value["origin"]?.string
            else { throw .clientData }
            let crossOrigin: Bool
            switch value["crossOrigin"] {
            case nil, .null?: crossOrigin = false
            case .bool(let flag)?: crossOrigin = flag
            default: throw .clientData
            }
            let topOrigin: String?
            switch value["topOrigin"] {
            case nil, .null?: topOrigin = nil
            case .string(let top)?: topOrigin = top
            default: throw .clientData
            }
            self.json = json
            self.type = type
            self.challenge = challenge
            self.origin = origin
            self.crossOrigin = crossOrigin
            self.topOrigin = topOrigin
        }

        /// The SHA-256 of `json`.
        public var hash: [UInt8] { W3C.WebAuthn.sha256(json) }
    }
}

extension W3C.WebAuthn.ClientData {

    /// Steps 7 to 10 of section 7.1, and 10 to 13 of section 7.2: the type, the challenge, the origin and the
    /// cross-origin context.
    func verify(
        type expectedType: String,
        challenge expectedChallenge: [UInt8],
        relyingParty: W3C.WebAuthn.RelyingParty
    ) throws(W3C.WebAuthn.Error) {
        guard type == expectedType else { throw .type(type) }
        guard W3C.WebAuthn.constantTimeEqual(challenge, expectedChallenge) else { throw .challenge }
        guard relyingParty.origins.contains(origin) else { throw .origin(origin) }
        if crossOrigin || topOrigin != nil {
            guard relyingParty.allowsCrossOrigin else { throw .crossOrigin }
            if let topOrigin {
                guard relyingParty.topOrigins.contains(topOrigin) else { throw .crossOrigin }
            }
        }
    }
}

extension W3C.WebAuthn {

    /// Whether `a` and `b` are equal, in time that depends only on their lengths.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices {
            difference |= a[index] ^ b[index]
        }
        return difference == 0
    }
}
