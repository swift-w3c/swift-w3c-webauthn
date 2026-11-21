internal import Byte
internal import FIPS_180_4
import W3C

extension W3C.WebAuthn {

    /// SHA-256, the hash of the RP ID and of `clientDataJSON`.
    static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        FIPS_180_4.SHA256.digest(bytes.map(Byte.init(_:))).bytes.map(\.underlying)
    }
}
