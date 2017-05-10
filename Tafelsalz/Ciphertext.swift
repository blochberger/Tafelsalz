import Foundation

public struct Ciphertext {
	let bytes: Data

	var sizeInBytes: PInt {
		get {
			return PInt(bytes.count)
		}
	}

	public init(_ bytes: Data) {
		self.bytes = bytes
	}
}
