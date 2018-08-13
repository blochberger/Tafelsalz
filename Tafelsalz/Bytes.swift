import Foundation

/**
	A convenience type representing a byte array.
*/
public typealias Bytes = Array<UInt8>

public extension Array where Element == UInt8 {

	/**
		Create a byte array filled with null bytes.

		- parameters:
			- count: The size of the byte array in bytes.
	*/
	public init(count: Int) {
		self.init(repeating: 0, count: count)
	}

	/**
		Return byte array as an hex encoded string.

		- postcondition: `bytes` = `bytes.hexlify.unhexlify()`
	*/
	public var hexlify: String {
		return sodium.bin2hex(self)
	}

	/**
		Return byte array as a Base64 encoded string.

		- postcondition: `bytes` = `bytes.b64encode().b64decode()`

		- returns: A Base64 encoded string.
	*/
	public func b64encode() -> String {
		return sodium.b64encode(bytes: self)
	}

}

public extension ArraySlice where Element == UInt8 {

	/**
		Turn the array slice into a byte array.
	*/
	public var bytes: Bytes {
		return Bytes(self)
	}

}

public extension String {

	/**
		A UTF-8-encoded byte array representation of the string.
	*/
	public var utf8Bytes: Bytes {
		return Bytes(self.utf8)
	}

	/**
		Turn a hex-encoded string into a byte array.

		- parameters:
			- ignore: A set of characters that should be ignored.

		- returns:
			A byte array if decoding is successful, `nil` else.
	*/
	public func unhexlify(ignore: String? = nil) -> Bytes? {
		return sodium.hex2bin(self, ignore: ignore)
	}

	/**
		Turn a Base64-encoded string into a byte array.

		- parameters:
			- ignore: A set of characters that should be ignored.

		- returns:
			A byte array if decoding is successful, `nil` else.
	*/
	public func b64decode(ignore: String? = nil) -> Bytes? {
		return sodium.b64decode(self, ignore: ignore)
	}

}

