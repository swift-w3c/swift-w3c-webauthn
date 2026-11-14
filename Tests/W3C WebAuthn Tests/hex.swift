/// The bytes a hexadecimal string spells, two digits per byte.
func hex(_ string: String) -> [UInt8] {
    let digits = Array(string.utf8)
    precondition(digits.count.isMultiple(of: 2))
    func value(_ digit: UInt8) -> UInt8 {
        switch digit {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): digit - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): digit - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): digit - UInt8(ascii: "A") + 10
        default: preconditionFailure("not a hexadecimal digit")
        }
    }
    return stride(from: 0, to: digits.count, by: 2).map { value(digits[$0]) << 4 | value(digits[$0 + 1]) }
}
