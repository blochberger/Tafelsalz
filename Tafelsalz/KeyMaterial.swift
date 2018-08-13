/**
	This class can be used to securely store key material in memory.
*/
public class KeyMaterial {

	/**
		The size of the key material in bytes.
	*/
	public var sizeInBytes: UInt32 { get { return memory.sizeInBytes } }

	/**
		The pointer to the secure memory location.
	*/
	private let memory: Memory

	/**
		This is the cached fingerprint.
	*/
	private var cachedHash: Bytes? = nil

	/**
		Initializes new key material of a given size.

		- parameters:
			- sizeInBytes: The size of the key material in bytes.
			- initialze: If `true`, then the allocated memory will be filled
				cryptographically secure random data, else it will be filled
				with `0xdb`.
	*/
	public init(sizeInBytes: UInt32, initialize: Bool = true) {
		let memory = Memory(sizeInBytes: sizeInBytes)

		if initialize {
			memory.withUnsafeMutableBytes {
				sodium.random.bytes($0, sizeInBytes: Int(sizeInBytes))
			}
		}

		self.memory = memory
	}

	/**
		Initializes key material by a given byte array. The byte array is copied
		to a secure memory location and overwritten with zeros afterwards in
		order to avoid the key material from being compromised.

		- parameters:
			- bytes: The key material.
	*/
	public init?(bytes: inout Bytes) {
		self.memory = Memory(&bytes)
	}

	/**
		Creates another instance pointing to the same secure memory location.
	
		- parameters:
			- other: Other key material.
	*/
	public init(_ other: KeyMaterial) {
		self.memory = other.memory
		self.cachedHash = other.cachedHash
	}

	/**
		Read raw bytes from the key material.

		Usually you do not need to call this function.

		- parameters:
			- body: A code block where the key material is readable.

		- returns: The result from the `body` code block.
	*/
	public func withUnsafeBytes<ResultType, ContentType>(body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		return try memory.withUnsafeBytes(body: body)
	}

	/**
		Make changes to the raw bytes of the key material.

		- warning:
			Use this with caution, as setting key material manually might lead
			to insecure key material.

		- parameters:
			- body: A code block where the key material is writable.

		- returns: The result from the `body` code block.
	*/
	func withUnsafeMutableBytes<ResultType, ContentType>(body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		return try memory.withUnsafeMutableBytes(body: body)
	}

	/**
		Copy the key material from the secure memory into an insecure byte
		array.

		- warning:
			Use this with caution, as the output is not located in secure
			memory.

		- returns: A copy of the key material.
	*/
	@inline(__always)
	public func copyBytes() -> Bytes {
		return withUnsafeBytes { Bytes(Data(bytes: $0, count: Int(sizeInBytes))) }
	}

	/**
		Returns a fingerprint of the key material. This can be used to compare
		key materials of different sizes.

		The fingerprint will only be calculated the first time this function is
		called.

		- returns: The fingerprint.
	*/
	func fingerprint() -> Bytes {
		if cachedHash == nil {
			cachedHash = withUnsafeBytes { sodium.generichash.hash(input: $0, inputSizeInBytes: UInt64(sizeInBytes)) }
		}

		return cachedHash!
	}

	/**
		Constant time comparison of the key material.

		- warning: Do not use if `other` might have a different size.

		- note:
			Explicitly do not conform to the `Equatable` protocol, as its
			invocation is determined statically. Therefore subclasses might end
			up being compared with this method. This can lead to problems if
			their sizes do not match, i.e. the application might crash or worse
			consider two instances equal if this instance is a prefix of the
			`other`. Hence, if a subclass is used to guarantee a fixed size,
			this method can safely called in an implementation of the `==`
			operator of the `Equatable` protocol. Then the compiler will only
			allow to compare instances of fixed length types. To compare
			instances of possibly different sizes, use
			`isFingerprintEqual(to:)`.

		- precondition: `sizeInBytes` = `other.sizeInBytes`

		- parameters:
			- other: Other key material to which this should be compared to.

		- returns: `true` if the key material is equal.
	*/
	func isEqual(to other: KeyMaterial) -> Bool {
		// This should never be called if the sizes do not match, as this would
		// allow timing attacks.
		precondition(sizeInBytes == other.sizeInBytes)

		return withUnsafeBytes {
			lhsPtr in

			return other.withUnsafeBytes {
				rhsPtr in

				return sodium.memory.areEqual(lhsPtr, rhsPtr, amountInBytes: Int(sizeInBytes))
			}
		}
	}

	/**
		Constant time comparison of the hash representing the key material.

		This can be used to compare instances that potentially have different
		sizes. If they are guaranteed to have the same size, use `isEqual(to:)`
		instead, as it is faster.

		- parameters:
			other: The key material to which this should be compared.

		- returns: `true` if both key materials have the same fingerprint.
	*/
	func isFingerprintEqual(to other: KeyMaterial) -> Bool {
		let hash = fingerprint()
		return sodium.memory.areEqual(hash, other.fingerprint(), amountInBytes: hash.count)
	}

}
