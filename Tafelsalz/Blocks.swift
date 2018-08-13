/**
	The padding mode for encryption and decryption. The same padding mode has to
	be used for encryption and decryption, else the decryption will fail.
*/
public enum Padding {

	/**
		This indicates that no padding should be used.

		- warning:
			If messages are encrypted without padding, the size of the message
			is disclosed. If that is unintended, use padding instead.
	*/
	case none

	/**
		This indicates that padding should be used. Padding is based on the
		given `blockSize`. The padded plaintext is a multiple of block size. If
		the unpadded plaintext is already a multiple of block size, an empty
		padding block is added.

		- parameters:
			- blockSize: The block size in bytes.
	*/
	case padded(blockSize: UInt32)
}

/**
	This structure represents padded plaintext. Blocks are acutally a byte array
	which is a multiple of a given block size.
*/
public struct Blocks {

	/**
		The size of a single block in bytes.
	*/
	public let blockSize: UInt32

	/**
		The padded plaintext bytes.
	*/
	public let bytes: Bytes

	/**
		Constructs a `Blocks` instance from unpadded plaintext. This will add
		padding to the plaintext bytes.

		- postcondition: `blocks.bytes.count` % `blocks.blockSize` = 0

		- parameters:
			- unpadded: The unpadded plaintext bytes.
			- blockSize: The size of a single block in bytes.

		- returns: `nil` if `blockSize` is 0.
	*/
	public init?(unpadded: Bytes, blockSize: UInt32) {
		guard 0 < blockSize else { return nil }

		self.blockSize = blockSize
		self.bytes = sodium.pad(unpadded: unpadded, blockSize: Int(blockSize))
	}

	/**
		Constructs a `Blocks` instance from padded plaintext.

		- parameters:
			- padded: The padded plaintext bytes.
			- blockSize: The size of a single block in bytes.

		- returns: `nil` if `blockSize` is 0 or if
			`padded.count` % `blockSize` ≠ 0
	*/
	public init?(padded: Bytes, blockSize: UInt32) {
		guard 0 < blockSize else { return nil }
		guard UInt32(padded.count) % blockSize == 0 else { return nil }
		guard sodium.unpad(padded: padded, blockSize: Int(blockSize)) != nil else { return nil }

		self.blockSize = blockSize
		self.bytes = padded
	}

	/**
		Return the plaintext without the padding.
	*/
	public var withoutPadding: Bytes {
		return sodium.unpad(padded: bytes, blockSize: Int(blockSize))!
	}

}
