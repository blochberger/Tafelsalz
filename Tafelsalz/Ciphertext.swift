import Foundation

public struct Ciphertext {
	public let bytes: Data

	public var sizeInBytes: PInt {
		get {
			return PInt(bytes.count)
		}
	}

	public init(_ bytes: Data) {
		self.bytes = bytes
	}
}
