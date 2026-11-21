public import W3C

extension W3C.WebAuthn {

    /// Why a registration or an assertion is refused. Each case names the step of section 7.1 or 7.2 that failed.
    public enum Error: Swift.Error, Sendable, Equatable {

        /// A response in its JSON form (section 5.1) that lacks a member, or whose binary member is not base64url.
        case response

        /// `clientDataJSON` is not a JSON object with string `type`, `challenge` and `origin` members, a boolean
        /// `crossOrigin` when present and a string `topOrigin` when present, or its challenge is not base64url.
        case clientData

        /// `type` is not `webauthn.create` for a registration or `webauthn.get` for an assertion.
        case type(String)

        /// The challenge is not the one the relying party issued.
        case challenge

        /// The origin is not one the relying party accepts.
        case origin(String)

        /// The ceremony ran in a cross-origin frame, or under a top origin, that the relying party does not accept.
        case crossOrigin

        /// The attestation object is not a CBOR map with a text `fmt`, a map `attStmt` and a byte string
        /// `authData`.
        case attestationObject

        /// The authenticator data is shorter than 37 bytes, its attested credential data or extensions are
        /// malformed, or bytes follow them (section 6.1).
        case authenticatorData

        /// `rpIdHash` is not the SHA-256 of the relying party ID.
        case relyingPartyID

        /// The user present flag is not set.
        case userPresence

        /// User verification is required and the user verified flag is not set.
        case userVerification

        /// The backed up flag is set without backup eligibility, or backup eligibility differs from the
        /// credential's.
        case backupState

        /// A registration's authenticator data has no attested credential data.
        case attestedCredentialData

        /// The credential ID is longer than 1023 bytes.
        case credentialID

        /// The credential public key is not a COSE key of an algorithm the relying party accepts.
        case algorithm

        /// The credential public key is not a valid key of its algorithm.
        case publicKey

        /// An attestation statement format this package does not verify.
        case attestationFormat(String)

        /// The attestation statement does not verify.
        case attestationStatement

        /// The signature is not a DER `Ecdsa-Sig-Value`, or does not verify.
        case signature

        /// The signature counter did not increase: the authenticator may have been cloned (section 6.1.1).
        case counter(stored: UInt32, received: UInt32)
    }
}
