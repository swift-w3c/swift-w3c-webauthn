internal import ISO_8824
internal import ISO_8825

extension W3C_WebAuthn {

    /// A credential public key of an algorithm this package verifies.
    public enum PublicKey: Sendable, Hashable {

        /// ES256: ECDSA over P-256 with SHA-256, from an EC2 COSE key with `alg` -7 and `crv` 1.
        case es256(FIPS_186_5.ECDSA.P256.PublicKey)
    }
}

extension W3C_WebAuthn.PublicKey {

    /// The public key a COSE key holds, when its algorithm is one of `algorithms` (section 7.1, step 18).
    ///
    /// The COSE key must name its algorithm, as section 6.5.1.1 requires.
    public init(_ key: RFC_9052.Key, algorithms: [RFC_9053.Algorithm] = [.es256]) throws(W3C_WebAuthn.Error) {
        guard let value = key.algorithm,
            let algorithm = RFC_9053.Algorithm(value),
            algorithms.contains(algorithm)
        else { throw .algorithm }
        switch algorithm {
        case .es256:
            let ec2: RFC_9053.EC2.PublicKey
            do {
                ec2 = try RFC_9053.EC2.PublicKey(key)
            } catch {
                throw .publicKey
            }
            guard ec2.curve == .p256, case .coordinate(let y) = ec2.y else { throw .publicKey }
            do {
                self = .es256(try FIPS_186_5.ECDSA.P256.PublicKey(x: ec2.x, y: y))
            } catch {
                throw .publicKey
            }
        default:
            throw .algorithm
        }
    }

    /// The public key encoded as a COSE key in `bytes`, as a relying party stores it.
    public init(cose bytes: [UInt8], algorithms: [RFC_9053.Algorithm] = [.es256]) throws(W3C_WebAuthn.Error) {
        let key: RFC_9052.Key
        do {
            key = try RFC_9052.Key(decoding: bytes)
        } catch {
            throw .publicKey
        }
        try self.init(key, algorithms: algorithms)
    }

    /// The algorithm.
    public var algorithm: RFC_9053.Algorithm {
        switch self {
        case .es256: .es256
        }
    }

    /// Whether `signature`, in the encoding the algorithm uses in WebAuthn (section 6.5.6), signs `message`.
    ///
    /// For ES256 that is an ASN.1 DER `Ecdsa-Sig-Value` (RFC 3279, section 2.2.3): a SEQUENCE of the INTEGERs r
    /// and s, in their shortest form.
    public func isValidSignature(_ signature: [UInt8], for message: [UInt8]) -> Bool {
        switch self {
        case .es256(let key):
            guard let decoded = Self.ecdsaSignature(der: signature) else { return false }
            return key.isValidSignature(decoded, for: message)
        }
    }

    /// The `(r, s)` of a DER `Ecdsa-Sig-Value`, or `nil` when the bytes are not one, or not one whose integers
    /// are positive and fit P-256.
    static func ecdsaSignature(der bytes: [UInt8]) -> FIPS_186_5.ECDSA.P256.Signature? {
        do {
            let node = try ISO_8825.DER.parse(bytes)
            let (r, s) = try ISO_8825.DER.sequence(node, identifier: .sequence) {
                (nodes: inout ISO_8825.Node.Collection.Iterator) throws(ISO_8824.Error) -> (ArraySlice<UInt8>, ArraySlice<UInt8>) in
                let r = try ArraySlice<UInt8>(derEncoded: &nodes)
                let s = try ArraySlice<UInt8>(derEncoded: &nodes)
                return (r, s)
            }
            return try FIPS_186_5.ECDSA.P256.Signature(r: Array(r), s: Array(s))
        } catch {
            return nil
        }
    }
}
