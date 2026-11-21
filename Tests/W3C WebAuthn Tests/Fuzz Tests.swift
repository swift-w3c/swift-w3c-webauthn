import Testing
import W3C_WebAuthn

struct Fuzzing: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }

    mutating func bytes(upTo limit: Int) -> [UInt8] {
        (0..<Int.random(in: 0...limit, using: &self)).map { _ in UInt8.random(in: .min ... .max, using: &self) }
    }

    mutating func mutate(_ bytes: [UInt8]) -> [UInt8] {
        var bytes = bytes
        for _ in 0..<Int.random(in: 1...4, using: &self) {
            switch Int.random(in: 0..<4, using: &self) {
            case 0 where !bytes.isEmpty:
                bytes[Int.random(in: bytes.indices, using: &self)] = UInt8.random(in: .min ... .max, using: &self)
            case 1 where !bytes.isEmpty:
                bytes.removeLast(Int.random(in: 1...bytes.count, using: &self))
            case 2:
                bytes.insert(UInt8.random(in: .min ... .max, using: &self), at: Int.random(in: 0...bytes.count, using: &self))
            default:
                bytes += [0xff, 0xff, 0xff, 0xff]
            }
        }
        return bytes
    }
}

@Suite(.timeLimit(.minutes(1)))
struct `Fuzz Tests` {
    static let rounds = 20_000

    @Test
    func `random bytes never crash the authenticator data, attestation object or client data readers`() {
        var random = Fuzzing(state: 0x5eed)
        var refused = 0
        for _ in 0..<Self.rounds {
            let bytes = random.bytes(upTo: 300)
            if (try? W3C.WebAuthn.AuthenticatorData(bytes)) == nil { refused += 1 }
            _ = try? W3C.WebAuthn.AttestationObject(bytes)
            _ = try? W3C.WebAuthn.ClientData(json: bytes)
        }
        #expect(refused > Self.rounds * 9 / 10)
    }

    @Test(arguments: Example.all)
    func `mutated examples are read or refused, never crash`(_ vector: Example.Vector) {
        var random = Fuzzing(state: 0xfacade)
        let sources = [hex(vector.attestationObject), hex(vector.authenticatorData), hex(vector.registrationClientDataJSON)]
        for _ in 0..<Self.rounds / 4 {
            _ = try? W3C.WebAuthn.AttestationObject(random.mutate(sources[0]))
            _ = try? W3C.WebAuthn.AuthenticatorData(random.mutate(sources[1]))
            _ = try? W3C.WebAuthn.ClientData(json: random.mutate(sources[2]))
        }
    }
}
