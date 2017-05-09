import Foundation
import libsodium

// <#TODO#> Offer method for securely persisting key material in system Keychain.

public class KeyMaterial {

	public let sizeInBytes: PInt
	private let bytesPtr: UnsafeMutableRawPointer

	var cachedHash: Data? = nil

	public init?(sizeInBytes: PInt) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard let bytesPtr = libsodium.sodium_malloc(Int(sizeInBytes)) else {
			return nil
		}

		libsodium.randombytes_buf(bytesPtr, Int(sizeInBytes))

		self.bytesPtr = bytesPtr
		self.sizeInBytes = sizeInBytes

		guard makeInaccessible() else {
			libsodium.sodium_free(bytesPtr)
			return nil
		}
	}

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

	deinit {
		guard makeReadWritable() else {
			abort()
		}

		libsodium.sodium_free(bytesPtr)
	}

	private func makeReadOnly() -> Bool {
		return libsodium.sodium_mprotect_readonly(bytesPtr) == 0
	}

	private func makeReadWritable() -> Bool {
		return libsodium.sodium_mprotect_readwrite(bytesPtr) == 0
	}

	private func makeInaccessible() -> Bool {
		return libsodium.sodium_mprotect_noaccess(bytesPtr) == 0
	}

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

	@inline(__always) public func copyBytes() -> Data {
		return withUnsafeBytes { Data(bytes: $0, count: Int(sizeInBytes)) }
	}

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
}

extension KeyMaterial: Equatable {
	public static func ==(lhs: KeyMaterial, rhs: KeyMaterial) -> Bool {

		guard let lhsHash = lhs.fingerprint() else {
			return false
		}

		guard let rhsHash = rhs.fingerprint() else {
			return false
		}

		return lhsHash.withUnsafeBytes {
			lhsHashPtr in

			return rhsHash.withUnsafeBytes {
				rhsHashPtr in

				return libsodium.memcmp(lhsHashPtr, rhsHashPtr, lhsHash.count) == 0
			}
		}
	}
}
