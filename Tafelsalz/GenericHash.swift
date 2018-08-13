/**
	This class can be used to generate hash arbitrary data. Keyed hashing is
	supported.

	- warning:
		Do not use this for hashing passwords, as there is no protection against
		fast brute-force attacks. Use `HashedPassword` for that purpose.
*/
public class GenericHash {

	/**
		This class represents a key that can be used for hashing.
	*/
	public class Key: KeyMaterial {
		/**
			The minimum size of the key in bytes.
		*/
		public static let MinimumSizeInBytes = UInt32(sodium.generichash.minimumKeySizeInBytes)

		/**
			The maximum size of the key in bytes.
		*/
		public static let MaximumSizeInBytes = UInt32(sodium.generichash.maximumKeySizeInBytes)

		/**
			The default key size in bytes.
		*/
		public static let DefaultSizeInBytes = UInt32(sodium.generichash.defaultKeySizeInBytes)

		/**
			Initialize a new key with a given size.

			The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
			`sizeInBytes` ≤ `MaximumSizeInBytes`.

			- parameters:
				- sizeInBytes: The size of the key in bytes.
		*/
		public init?(sizeInBytes: UInt32) {
			guard Key.MinimumSizeInBytes <= sizeInBytes && sizeInBytes <= Key.MaximumSizeInBytes else {
				return nil
			}
			// <#TODO#> Use `libsodium.crypto_generichash_keygen()` but only works
			// for `DefaultSizeInBytes`, see
			// https://github.com/jedisct1/libsodium/commit/7f7e7235c52f13800df15ef705dbd199252a784c#commitcomment-23597389
			super.init(sizeInBytes: sizeInBytes)
		}

		/**
			Initialize a new key with the default size.
		*/
		public convenience init() {
			self.init(sizeInBytes: Key.DefaultSizeInBytes)!
		}

		/**
			Restores a key from a given byte array. The byte array is copied to
			a secure location and overwritten with zeroes to avoid the key being
			compromised in memory.

			- warning:
				Do not initialize new keys with this function. If you need a new
				key, use `init?(sizeInBytes:)` instead. This initializer is only
				to restore secret keys that were persisted.

			- parameters:
				- bytes: The key.
		*/
		public override init?(bytes: inout Bytes) {
			guard Key.MinimumSizeInBytes <= UInt32(bytes.count) && UInt32(bytes.count) <= Key.MaximumSizeInBytes else {
				return nil
			}
			super.init(bytes: &bytes)
		}

		/**
			Restores a key from a given hex string.

			- warning:
				Do not initialize new keys with this function. If you need a new
				key, use `init?(sizeInBytes:)` instead. This initializer is only
				to restore secret keys that were persisted.

			- parameters:
				- hex: The key as a hex encoded string.
				- ignore: A character set that should be ignored when decoding
					the key.

			- see: `Data(hex:ignore:)`
		*/
		public convenience init?(hex: String, ignore: String? = nil) {
			guard var bytes = hex.unhexlify(ignore: ignore) else {
				return nil
			}

			self.init(bytes: &bytes)
		}

		/**
			Creates a hashing key from other key material.

			- precondition:
				`MinimumSizeInBytes` ≤ `other.sizeInBytes` ≤ `MaximumSizeInBytes`

			- parameters:
				- other: The other key material.
		*/
		override init(_ other: KeyMaterial) {
			precondition(Key.MinimumSizeInBytes <= other.sizeInBytes)
			precondition(other.sizeInBytes <= Key.MaximumSizeInBytes)

			super.init(other)
		}
	}

	/**
		The minimum size of the hash in bytes.
	*/
	public static let MinimumSizeInBytes = UInt32(sodium.generichash.minimumOutputSizeInBytes)

	/**
		The maximum size of the hash in bytes.
	*/
	public static let MaximumSizeInBytes = UInt32(sodium.generichash.maximumOutputSizeInBytes)

	/**
		The default size of the hash in bytes.
	*/
	public static let DefaultSizeInBytes = UInt32(sodium.generichash.defaultOutputSizeInBytes)

	/**
		The hash.
	*/
	private let bytes: Bytes

	/**
		Hash an arbitrary value.

		The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
		`outputSizeInBytes` ≤ `MaximumSizeInBytes`.

		- warning:
			Do not use this for hashing passwords, as there is no protection
			against fast brute-force attacks. Use `HashedPassword` for that
			purpose.

			This is not protected against rainbow attacks if you do not provide
			a key.

		- parameters:
			- bytes: The value that should be hashed.
			- outputSizeInBytes: The size of the hash in bytes.
			- key: A key/salt used to prevent the hash from being guessed.
	*/
	public init?(bytes: Bytes, outputSizeInBytes: UInt32 = GenericHash.DefaultSizeInBytes, with key: Key? = nil) {

		guard GenericHash.MinimumSizeInBytes <= outputSizeInBytes && outputSizeInBytes <= GenericHash.MaximumSizeInBytes else {
			return nil
		}

		let result: Bytes

		if let key = key {
			result = key.withUnsafeBytes {
				(keyPtr: UnsafePointer<UInt8>) -> Bytes in

				return sodium.generichash.hash(
					outputSizeInBytes: Int(outputSizeInBytes),
					input: bytes,
					inputSizeInBytes: UInt64(bytes.count),
					key: keyPtr,
					keySizeInBytes: Int(key.sizeInBytes)
				)
			}
		} else {
			result = sodium.generichash.hash(
				outputSizeInBytes: Int(outputSizeInBytes),
				input: bytes,
				inputSizeInBytes: UInt64(bytes.count)
			)
		}

		self.bytes = result
	}

	/**
		Hash an arbitrary value for a given persona.

		The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
		`outputSizeInBytes` ≤ `MaximumSizeInBytes`.

		This is protected against rainbow attacks.

		- warning:
			Do not use this for hashing passwords, as there is no protection
			against fast brute-force attacks. Use `HashedPassword` for that
			purpose.

		- parameters:
			- bytes: The value that should be hashed.
			- persona: The persona to which the hash is tied to.
			- outputSizeInBytes: The size of the hash in bytes.
	*/
	public convenience init?(bytes: Bytes, for persona: Persona, outputSizeInBytes: UInt32 = GenericHash.DefaultSizeInBytes) {
		guard let key = try? persona.genericHashKey() else { return nil }
		self.init(bytes: bytes, outputSizeInBytes: outputSizeInBytes, with: key)
	}

	/**
		Restore a hash from a hex string.

		- parameters:
			- hex: The hash as a hex encoded string.
	*/
	public init?(hex: String) {
		guard let bytes = hex.unhexlify() else { return nil }
		guard GenericHash.MinimumSizeInBytes <= UInt32(bytes.count) else { return nil }
		guard UInt32(bytes.count) <= GenericHash.MaximumSizeInBytes else { return nil }

		self.bytes = bytes
	}

	/**
		The size of the hash in bytes.
	*/
	public var sizeInBytes: UInt32 {
		return UInt32(bytes.count)
	}

	/**
		A hex encoded string representing the hash.
	*/
	public var hexlify: String {
		return bytes.hexlify
	}
}

extension GenericHash: Equatable {
	/**
		Compares two hashes in constant time.

		- note:
			An attacker might be able to identify the length of the hash with a
			timing attack. But as the size bounds for hashes are publicly known
			and the minimum size is sufficiently long, this should not be a
			cause for problems.

		- parameters:
			- lhs: A hash.
			- rhs: Another hash.

		- returns:
			`true` if both hashes are equal, `false` else.
	*/
	public static func ==(lhs: GenericHash, rhs: GenericHash) -> Bool {
		guard lhs.sizeInBytes == rhs.sizeInBytes else {
			return false
		}

		return sodium.memory.areEqual(lhs.bytes, rhs.bytes, amountInBytes: Int(lhs.sizeInBytes))
	}
}

extension GenericHash: Hashable {
	/**
		The hash value according to the [`Hashable`](https://developer.apple.com/documentation/swift/hashable)
		protocol.

		- warning:
			This is **not** the value of the generic hash but a value used for
			improving performance of data structures.
	*/
	public var hashValue: Int {
		return Data(self.bytes).hashValue
	}
}
