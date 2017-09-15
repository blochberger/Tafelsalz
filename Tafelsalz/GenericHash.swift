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
		public static let MinimumSizeInBytes = PInt(sodium.generichash.minimumKeySizeInBytes)

		/**
			The maximum size of the key in bytes.
		*/
		public static let MaximumSizeInBytes = PInt(sodium.generichash.maximumKeySizeInBytes)

		/**
			The default key size in bytes.
		*/
		public static let DefaultSizeInBytes = PInt(sodium.generichash.defaultKeySizeInBytes)

		/**
			Initialize a new key with a given size.

			The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
			`sizeInBytes` ≤ `MaximumSizeInBytes`.

			- parameters:
				- sizeInBytes: The size of the key in bytes.
		*/
		public init?(sizeInBytes: PInt) {
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
		public override init?(bytes: inout Data) {
			guard Key.MinimumSizeInBytes <= PInt(bytes.count) && PInt(bytes.count) <= Key.MaximumSizeInBytes else {
				return nil
			}
			super.init(bytes: &bytes)
		}

		/**
			Restores a key from a given hex string.

			- note:
				All characters until the first non-hex character will be taken
				into account, when restoring the key.

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
			var bytes = Data(hex: hex, ignore: ignore)
			self.init(bytes: &bytes)
		}
	}

	/**
		The minimum size of the hash in bytes.
	*/
	public static let MinimumSizeInBytes = PInt(sodium.generichash.minimumOutputSizeInBytes)

	/**
		The maximum size of the hash in bytes.
	*/
	public static let MaximumSizeInBytes = PInt(sodium.generichash.maximumOutputSizeInBytes)

	/**
		The default size of the hash in bytes.
	*/
	public static let DefaultSizeInBytes = PInt(sodium.generichash.defaultOutputSizeInBytes)

	/**
		The hash.
	*/
	fileprivate let bytes: Data

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
	public init?(bytes: Data, outputSizeInBytes: PInt = GenericHash.DefaultSizeInBytes, with key: Key? = nil) {

		guard GenericHash.MinimumSizeInBytes <= outputSizeInBytes && outputSizeInBytes <= GenericHash.MaximumSizeInBytes else {
			return nil
		}

		let result = bytes.withUnsafeBytes {
			(bytesPtr: UnsafePointer<UInt8>) -> Data in

			if let key = key {
				return key.withUnsafeBytes {
					(keyPtr: UnsafePointer<UInt8>) -> Data in

					return sodium.generichash.hash(
						outputSizeInBytes: Int(outputSizeInBytes),
						input: bytesPtr,
						inputSizeInBytes: UInt64(bytes.count),
						key: keyPtr,
						keySizeInBytes: Int(key.sizeInBytes)
					)
				}
			} else {
				return sodium.generichash.hash(
					outputSizeInBytes: Int(outputSizeInBytes),
					input: bytesPtr,
					inputSizeInBytes: UInt64(bytes.count)
				)
			}
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
	public convenience init?(bytes: Data, for persona: Persona, outputSizeInBytes: PInt = GenericHash.DefaultSizeInBytes) {
		guard let key = try? persona.genericHashKey() else { return nil }
		self.init(bytes: bytes, outputSizeInBytes: outputSizeInBytes, with: key)
	}

	/**
		Restore a hash from a hex string.

		- parameters:
			- hex: The hash as a hex encoded string.
	*/
	public init?(hex: String) {
		let bytes = Data(hex: hex)
		guard GenericHash.MinimumSizeInBytes <= PInt(bytes.count) else { return nil }
		guard PInt(bytes.count) <= GenericHash.MaximumSizeInBytes else { return nil }

		self.bytes = bytes
	}

	/**
		The size of the hash in bytes.
	*/
	public var sizeInBytes: PInt { get { return PInt(bytes.count) } }

	/**
		A hex encoded string representing the hash.
	*/
	public var hex: String? { get { return bytes.hex } }
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

		return lhs.bytes.withUnsafeBytes {
			lhsPtr in

			return rhs.bytes.withUnsafeBytes {
				rhsPtr in

				return sodium.memory.areEqual(lhsPtr, rhsPtr, amountInBytes: Int(lhs.sizeInBytes))
			}
		}
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
		get {
			return self.bytes.hashValue
		}
	}
}
