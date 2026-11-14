extension W3C_WebAuthn {

    /// Verifying an authentication ceremony (section 7.2).
    public enum Assertion {}
}

extension W3C_WebAuthn.Assertion {

    /// The credential as it stands after a verified assertion: its counter, backup state and user verification
    /// updated (section 7.2, steps 21 to 24).
    ///
    /// - Parameters:
    ///   - clientDataJSON: `response.clientDataJSON`.
    ///   - authenticatorData: `response.authenticatorData`.
    ///   - signature: `response.signature`.
    ///   - challenge: the challenge the relying party issued for this ceremony; it must be used once only.
    ///   - relyingParty: what the relying party accepts.
    ///   - credential: the stored credential whose ID is the assertion's `rawId`.
    ///
    /// Finding the credential by its ID, and checking `response.userHandle` against its owner (steps 5 and 6),
    /// is the relying party's. A counter that did not increase throws `.counter`, so the relying party can flag
    /// the credential as possibly cloned.
    public static func verify(
        clientDataJSON: [UInt8],
        authenticatorData: [UInt8],
        signature: [UInt8],
        challenge: [UInt8],
        relyingParty: W3C_WebAuthn.RelyingParty,
        credential: W3C_WebAuthn.Credential
    ) throws(W3C_WebAuthn.Error) -> W3C_WebAuthn.Credential {
        // Steps 7 to 14.
        let clientData = try W3C_WebAuthn.ClientData(json: clientDataJSON)
        try clientData.verify(type: "webauthn.get", challenge: challenge, relyingParty: relyingParty)

        // Steps 15 to 18.
        let data = try W3C_WebAuthn.AuthenticatorData(authenticatorData)
        try data.verify(relyingParty: relyingParty)
        guard data.flags.contains(.backupEligible) == credential.backupEligible else { throw .backupState }

        // Steps 20 and 21.
        let publicKey = try W3C_WebAuthn.PublicKey(cose: credential.publicKey, algorithms: relyingParty.algorithms)
        guard publicKey.isValidSignature(signature, for: authenticatorData + clientData.hash) else {
            throw .signature
        }

        // Step 22.
        if data.signCount != 0 || credential.signCount != 0 {
            guard data.signCount > credential.signCount else {
                throw .counter(stored: credential.signCount, received: data.signCount)
            }
        }

        var updated = credential
        updated.signCount = data.signCount
        updated.backedUp = data.flags.contains(.backedUp)
        updated.userVerified = data.flags.contains(.userVerified)
        return updated
    }
}
