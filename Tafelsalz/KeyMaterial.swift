import Foundation
import libsodium

/**
	This class can be used to securely store key material in memory.
*/
public class KeyMaterial {

	/**
		The size of the key material in bytes.
	*/
	public let sizeInBytes: PInt

	/**
		The pointer to the secure memory location.
	*/
	private let bytesPtr: UnsafeMutableRawPointer

	/**
		This is the cached fingerprint.
	*/
	private var cachedHash: Data? = nil

	/**
		Initializes new key material of a given size.

		- parameters:
			- sizeInBytes: The size of the key material in bytes.
			- initialze: If `true`, then the allocated memory will be filled
				cryptographically secure random data, else it will be filled
				with `0xdb`.

		- see: [Guarded heap allocations](https://download.libsodium.org/doc/helpers/memory_management.html#guarded-heap-allocations)
	*/
	public init?(sizeInBytes: PInt, initialize: Bool = true) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard let bytesPtr = libsodium.sodium_malloc(Int(sizeInBytes)) else {
			return nil
		}

		if initialize {
			libsodium.randombytes_buf(bytesPtr, Int(sizeInBytes))
		}

		self.bytesPtr = bytesPtr
		self.sizeInBytes = sizeInBytes

		guard makeInaccessible() else {
			libsodium.sodium_free(bytesPtr)
			return nil
		}
	}

	/**
		Initializes key material by a given byte array. The byte array is copied
		to a secure memory location and overwritten with zeros afterwards in
		order to avoid the key material from being compromised.

		- parameters:
			- bytes: The key material.
	*/
	public init?(bytes: inout Data) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard let bytesPtr = libsodium.sodium_malloc(bytes.count) else {
			return nil
		}

		self.bytesPtr = bytesPtr
		self.sizeInBytes = PInt(bytes.count)

		bytes.withUnsafeBytes {
			bytesPtr in

			self.bytesPtr.copyBytes(from: bytesPtr, count: bytes.count)
		}

		guard makeInaccessible() else {
			libsodium.sodium_free(bytesPtr)
			return nil
		}

		bytes.withUnsafeMutableBytes {
			bytesPtr in

			libsodium.sodium_memzero(bytesPtr, bytes.count)
		}
	}

	/**
		Deletes key material. The memory is overwritten with zeroes.

		- see: [Guarded heap allocations](https://download.libsodium.org/doc/helpers/memory_management.html#guarded-heap-allocations)
	*/
	deinit {
		guard makeReadWritable() else {
			abort()
		}

		libsodium.sodium_free(bytesPtr)
	}

	/**
		Make the memory location where the key material is stored read only.

		- returns: `true` on success.
	*/
	private func makeReadOnly() -> Bool {
		return libsodium.sodium_mprotect_readonly(bytesPtr) == 0
	}

	/**
		Make the memory location where the key material is stored writable.

		- returns: `true` on success.
	*/
	private func makeReadWritable() -> Bool {
		return libsodium.sodium_mprotect_readwrite(bytesPtr) == 0
	}

	/**
		Make the memory location where the key material is stored inaccessible.

		- returns: `true` on success.
	*/
	private func makeInaccessible() -> Bool {
		return libsodium.sodium_mprotect_noaccess(bytesPtr) == 0
	}

	/**
		Read raw bytes from the key material.

		Usually you do not need to call this function.

		- parameters:
			- body: A code block where the key material is readable.

		- returns: The result from the `body` code block.
	*/
	public func withUnsafeBytes<ResultType, ContentType>(body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		guard makeReadOnly() else {
			abort()
		}

		let result = try body(UnsafeRawPointer(bytesPtr).bindMemory(to: ContentType.self, capacity: Int(sizeInBytes)))

		guard makeInaccessible() else {
			abort()
		}

		return result
	}

	/**
		Make changes to the raw bytes of the key material.

		- warning: Use this with caution, as setting key material manually might
			lead to insecure key material.

		- parameters:
			- body: A code block where the key material is writable.

		- returns: The result from the `body` code block.
	*/
	func withUnsafeMutableBytes<ResultType, ContentType>(body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		guard makeReadWritable() else {
			abort()
		}

		let result = try body(UnsafeMutableRawPointer(bytesPtr).bindMemory(to: ContentType.self, capacity: Int(sizeInBytes)))

		guard makeInaccessible() else {
			abort()
		}

		return result
	}

	/**
		Copy the key material from the secure memory into an insecure byte
		array.

		- warning: Use this with caution, as the output is not located in secure
			memory.

		- returns: A copy of the key material.
	*/
	@inline(__always)
	public func copyBytes() -> Data {
		return withUnsafeBytes { Data(bytes: $0, count: Int(sizeInBytes)) }
	}

	/**
		Returns a fingerprint of the key material. This can be used to compare
		key materials of different sizes.

		The fingerprint will only be calculated the first time this function is
		called.

		- returns: The fingerprint.
	*/
	func fingerprint() -> Data? {
		if cachedHash == nil {
			let hashSize = libsodium.crypto_generichash_bytes()

			var uncachedHash = Data(count: hashSize)

			let success = uncachedHash.withUnsafeMutableBytes {
				uncachedHashPtr in

				return withUnsafeBytes {
					bytesPtr in

					return libsodium.crypto_generichash(
						uncachedHashPtr,
						hashSize,
						bytesPtr,
						UInt64(sizeInBytes),
						nil,
						0
					) == 0
				}
			}

			guard success else {
				return nil
			}

			cachedHash = uncachedHash
		}

		return cachedHash
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

		- precondition:

			```swift
			self.sizeInBytes == other.sizeInBytes
			```
	
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

				return libsodium.sodium_memcmp(lhsPtr, rhsPtr, Int(sizeInBytes)) == 0
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
		guard let lhsHash = fingerprint() else {
			return false
		}

		guard let rhsHash = other.fingerprint() else {
			return false
		}

		return lhsHash.withUnsafeBytes {
			lhsHashPtr in

			return rhsHash.withUnsafeBytes {
				rhsHashPtr in

				return libsodium.sodium_memcmp(lhsHashPtr, rhsHashPtr, lhsHash.count) == 0
			}
		}

	}

}
