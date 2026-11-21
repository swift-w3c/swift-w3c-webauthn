public import W3C

extension W3C.WebAuthn {

    /// Verifying a registration ceremony (section 7.1).
    public enum Registration {}
}

extension W3C.WebAuthn.Registration {

    /// The credential a registration created, after every check of section 7.1 this package can make.
    ///
    /// - Parameters:
    ///   - clientDataJSON: `response.clientDataJSON`.
    ///   - attestationObject: `response.attestationObject`.
    ///   - challenge: the challenge the relying party issued for this ceremony; it must be used once only.
    ///   - relyingParty: what the relying party accepts.
    ///
    /// Attestation formats `none` and `packed` self attestation are verified; any other format, and `packed`
    /// with a certificate chain, is refused, since no trust anchors are configured. The relying party still
    /// checks that the credential ID is not registered already (step 25).
    public static func verify(
        clientDataJSON: [UInt8],
        attestationObject: [UInt8],
        challenge: [UInt8],
        relyingParty: W3C.WebAuthn.RelyingParty
    ) throws(W3C.WebAuthn.Error) -> W3C.WebAuthn.Credential {
        let clientData = try W3C.WebAuthn.ClientData(json: clientDataJSON)
        try clientData.verify(type: "webauthn.create", challenge: challenge, relyingParty: relyingParty)

        let object = try W3C.WebAuthn.AttestationObject(attestationObject)
        let authenticatorData = object.authenticatorData
        try authenticatorData.verify(relyingParty: relyingParty)
        guard let attested = authenticatorData.attestedCredentialData else { throw .attestedCredentialData }

        let publicKey = try W3C.WebAuthn.PublicKey(attested.publicKey, algorithms: relyingParty.algorithms)
        guard attested.credentialID.count <= 1023 else { throw .credentialID }

        try verifyStatement(
            format: object.format,
            statement: RFC_8949.Value.map(object.statement),
            authenticatorData: authenticatorData.bytes,
            clientDataHash: clientData.hash,
            publicKey: publicKey
        )

        return W3C.WebAuthn.Credential(
            id: attested.credentialID,
            publicKey: attested.publicKeyBytes,
            signCount: authenticatorData.signCount,
            aaguid: attested.aaguid,
            backupEligible: authenticatorData.flags.contains(.backupEligible),
            backedUp: authenticatorData.flags.contains(.backedUp),
            userVerified: authenticatorData.flags.contains(.userVerified),
            attestationFormat: object.format
        )
    }

    private static func verifyStatement(
        format: String,
        statement: RFC_8949.Value,
        authenticatorData: [UInt8],
        clientDataHash: [UInt8],
        publicKey: W3C.WebAuthn.PublicKey
    ) throws(W3C.WebAuthn.Error) {
        switch format {
        case "none":
            guard statement.map?.isEmpty == true else { throw .attestationStatement }

        case "packed":
            guard statement["x5c"] == nil else { throw .attestationFormat(format) }
            guard let pairs = statement.map, pairs.count == 2,
                let alg = statement["alg"], RFC_9053.Algorithm(alg) == publicKey.algorithm,
                let signature = statement["sig"]?.bytes
            else { throw .attestationStatement }
            guard publicKey.isValidSignature(signature, for: authenticatorData + clientDataHash) else {
                throw .attestationStatement
            }

        default:
            throw .attestationFormat(format)
        }
    }
}
