internal import ASCII
internal import Byte
internal import RFC_4648
import W3C

extension W3C.WebAuthn {

    /// Base64url without padding, the encoding of binary members in WebAuthn's JSON (section 5.1).
    enum Base64URL {}
}

extension W3C.WebAuthn.Base64URL {

    static func encode(_ bytes: [UInt8]) -> String {
        let codes = RFC_4648.Base64.URL.encode(bytes.map(Byte.init(_:)), padding: false)
        return String(decoding: codes.map(\.underlying), as: UTF8.self)
    }

    static func decode(_ string: String) -> [UInt8]? {
        guard !string.contains("=") else { return nil }
        return RFC_4648.Base64.URL.decode(string, strictness: .strict)?.map(\.underlying)
    }
}
