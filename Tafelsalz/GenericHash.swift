import Foundation

import libsodium

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
		public static let MinimumSizeInBytes = PInt(libsodium.crypto_generichash_keybytes_min())

		/**
			The maximum size of the key in bytes.
		*/
		public static let MaximumSizeInBytes = PInt(libsodium.crypto_generichash_keybytes_max())

		/**
			The default key size in bytes.
		*/
		public static let DefaultSizeInBytes = PInt(libsodium.crypto_generichash_keybytes())

		/**
			Initialize a new key with a given size.
		
			The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
			`sizeInBytes` ≤ `MaximumSizeInBytes`.
		
			- parameters:
				- sizeInBytes: The size of the key in bytes.
		*/
		public init?(sizeInBytes: PInt = Key.DefaultSizeInBytes) {
			guard Key.MinimumSizeInBytes <= sizeInBytes && sizeInBytes <= Key.MaximumSizeInBytes else {
				return nil
			}
			// <#TODO#> Use `libsodium.crypto_generichash_keygen()` but only works
			// for `DefaultSizeInBytes`, see
			// https://github.com/jedisct1/libsodium/commit/7f7e7235c52f13800df15ef705dbd199252a784c#commitcomment-23597389
			super.init(sizeInBytes: sizeInBytes)
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
			guard var bytes = Data(hex: hex, ignore: ignore) else { return nil }
			self.init(bytes: &bytes)
		}
	}

	/**
		The minimum size of the hash in bytes.
	*/
	public static let MinimumSizeInBytes = PInt(libsodium.crypto_generichash_bytes_min())

	/**
		The maximum size of the hash in bytes.
	*/
	public static let MaximumSizeInBytes = PInt(libsodium.crypto_generichash_bytes_max())

	/**
		The default size of the hash in bytes.
	*/
	public static let DefaultSizeInBytes = PInt(libsodium.crypto_generichash_bytes())

	/**
		The hash.
	*/
	private let bytes: Data

	/**
		Hash an arbitrary value.
	
		The size needs to be within the given bounds: `MinimumSizeInBytes` ≤
		`outputSizeInBytes` ≤ `MaximumSizeInBytes`.

		- warning:
			Do not use this for hashing passwords, as there is no protection
			against fast brute-force attacks. Use `HashedPassword` for that
			purpose.

		- parameters:
			- bytes: The value that should be hashed.
			- outputSizeInBytes: The size of the hash in bytes.
			- key: A key/salt used to prevent the hash from being guessed.
	*/
	init?(bytes: Data, outputSizeInBytes: PInt = GenericHash.DefaultSizeInBytes, with key: Key? = nil) {

		guard GenericHash.MinimumSizeInBytes <= outputSizeInBytes && outputSizeInBytes <= GenericHash.MaximumSizeInBytes else {
			return nil
		}

		var result = Data(count: Int(outputSizeInBytes))

		let success = result.withUnsafeMutableBytes {
			(resultPtr: UnsafeMutablePointer<UInt8>) -> Bool in

			return bytes.withUnsafeBytes {
				(bytesPtr: UnsafePointer<UInt8>) -> Bool in

				if let key = key {
					return key.withUnsafeBytes {
						(keyPtr: UnsafePointer<UInt8>) -> Bool in

						return libsodium.crypto_generichash(
							resultPtr,
							Int(outputSizeInBytes),
							bytesPtr,
							UInt64(bytes.count),
							keyPtr,
							Int(key.sizeInBytes)
						) == 0
					}
				} else {
					return libsodium.crypto_generichash(
						resultPtr,
						Int(outputSizeInBytes),
						bytesPtr,
						UInt64(bytes.count),
						nil,
						0
					) == 0
				}
			}
		}

		guard success else { return nil }

		self.bytes = result
	}

	/**
		The size of the hash in bytes.
	*/
	var sizeInBytes: PInt { get { return PInt(bytes.count) } }

	/**
		A hex encoded string representing the hash.
	*/
	var hex: String? { get { return bytes.hex } }
}
