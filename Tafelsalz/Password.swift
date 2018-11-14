/**
	This class can be used to securely handle passwords. Passwords will be
	copied to a secure memory location, comparison will be performed in constant
	time to avoid timing attacks and a method for hashing passwords is provided
	to store them for user authentication purposes.

	## Examples

	```swift
	let password = Password("Correct Horse Battery Staple")!
	let hashedPassword = password.hash()!

	// Store `hashedPassword.string` to database.

	// If a user wants to authenticate, just read it from the database and
	// verify it against the password given by the user.
	if hashedPassword.isVerified(by: password) {
	    // The user is authenticated successfully.
	}
	```
*/
public class Password {

	/**
		Defines how much CPU load will be required for hashing a password. This
		reduces the speed of brute-force attacks. You might be required to chose
		`high` or `medium` if your device does not have much CPU power.

		- see: [Guidelines for choosing the parameters](https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html#guidelines-for-choosing-the-parameters)
	*/
	public enum ComplexityLimit {
		/**
			This is the fastest option and should be avoided if possible.
		*/
		case medium

		/**
			This takes about 0.7 seconds on a 2.8 Ghz Core i7 CPU.
		*/
		case high

		/**
			This takes about 3.5 seconds on a 2.8 Ghz Core i7 CPU.
		*/
		case veryHigh

		/**
			Helper function to translate the `ComplexityLimit` enum to the
			values expected by `libsodium`.

			- returns: The complexity limit that can be interpreted by
				`libsodium`.
		*/
		fileprivate var sodiumValue: Int {
			switch self {
				case .medium:
					return sodium.pwhash.opslimit_interactive
				case .high:
					return sodium.pwhash.opslimit_moderate
				case .veryHigh:
					return sodium.pwhash.opslimit_sensitive
			}
		}

		/**
			Translates a given value from `libsodium` to a corresponding enum
			value.

			- parameters:
				- value: The complexity limit that can be interpreted by
					libsodium.
		*/
		fileprivate init?(value: Int) {
			switch value {
				case ComplexityLimit.medium.sodiumValue:
					self = .medium
				case ComplexityLimit.high.sodiumValue:
					self = .high
				case ComplexityLimit.veryHigh.sodiumValue:
					self = .veryHigh
				default:
					return nil
			}
		}
	}

	/**
		Defines how much memory will be required for hashing a password. This
		makes brute-forcing more costly. The speed requirements induced by
		increased CPU load can be reduced by massively parallelizing the attack
		using FPGAs. As these have limited memory, this factor mitigates those
		attacks. You might be required to chose `high` or `medium` if your
		device is not equipped with much memory.

		- see: [Guidelines for choosing the parameters](https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html#guidelines-for-choosing-the-parameters)
	*/
	public enum MemoryLimit {
		/**
			This requires about 64 MiB memory.
		*/
		case medium

		/**
			This requires about 256 MiB memory.
		*/
		case high

		/**
			This requires about 1 GiB memory.
		*/
		case veryHigh

		/**
			Helper function to translate the `MemoryLimit` enum to the values
			expected by `libsodium`.

			- returns: The memory limit that can be interpreted by `libsodium`.
		*/
		fileprivate var sodiumValue: Int {
			switch self {
				case .medium:
					return sodium.pwhash.memlimit_interactive
				case .high:
					return sodium.pwhash.memlimit_moderate
				case .veryHigh:
					return sodium.pwhash.memlimit_sensitive
			}
		}

		/**
			Translates a given value from `libsodium` to a corresponding enum
			value.

			- parameters:
				- value: The complexity limit that can be interpreted by
					libsodium.
		*/
		fileprivate init?(value: Int) {
			switch value {
				case MemoryLimit.medium.sodiumValue:
					self = .medium
				case MemoryLimit.high.sodiumValue:
					self = .high
				case MemoryLimit.veryHigh.sodiumValue:
					self = .veryHigh
				default:
					return nil
			}
		}
	}

	/**
		A salt should be applied to passwords prior to hashing in order to
		prevent dictionary attacks. This class represents such a salt.
	*/
	public struct Salt {

		/**
			The size of the salt in bytes.
		*/
		public static let SizeInBytes = UInt32(sodium.pwhash.sizeOfSaltInBytes)

		/**
			The actual salt bytes.
		*/
		public let bytes: Bytes

		/**
			Initializes a random salt.
		*/
		public init() {
			self.bytes = Random.bytes(count: Password.Salt.SizeInBytes)
		}

		/**
			Initializes a salt from a byte array.

			- warning: This should only be used to reconstruct salt bytes
				generated with `Salt()`. Do not use this for hardcoded values.

			- parameters:
				- bytes: The bytes of the salt.
		*/
		public init?(bytes: Bytes) {
			guard bytes.count == Salt.SizeInBytes else {
				return nil
			}

			self.bytes = bytes
		}

	}

	/**
		A key that is derived from a `Password`.

		A derived key contains additional information, i.e., the parameters used
		to derive the key. In order to derive the same key from the password,
		the same parameters have to be used.
	*/
	public class DerivedKey: KeyMaterial {

		/**
			Minimum size of the derived key in bytes.
		*/
		public static let MinimumSizeInBytes = UInt32(sodium.pwhash.minimumKeySizeInBytes)

		/**
			Maximum size of the derived key in bytes.
		*/
		public static let MaximumSizeInBytes = UInt32(sodium.pwhash.maximumKeySizeInBytes)

		/**
			Size of the public parameters, serialized to a byte array.
		*/
		public static let SizeOfPublicParametersInBytes = UInt32(2 * MemoryLayout<UInt32>.size + Int(Salt.SizeInBytes))

		/**
			The salt used for deriving the key.
		*/
		let salt: Salt

		/**
			The complexity limit used for deriving the key.
		*/
		let complexityLimit: ComplexityLimit

		/**
			The memory limit used for deriving the key.
		*/
		let memoryLimit: MemoryLimit

		/**
			A byte array containing all the parameters required to derive the
			same key for the given password.
		*/
		public var publicParameters: Bytes {
			var result = Bytes()

			let opslimit = UInt32(complexityLimit.sodiumValue)
			result.append(UInt8(opslimit >> 24))
			result.append(UInt8((opslimit >> 16) & 0xFF))
			result.append(UInt8((opslimit >> 8) & 0xFF))
			result.append(UInt8(opslimit & 0xFF))

			let memlimit = UInt32(memoryLimit.sodiumValue)
			result.append(UInt8(memlimit >> 24))
			result.append(UInt8((memlimit >> 16) & 0xFF))
			result.append(UInt8((memlimit >> 8) & 0xFF))
			result.append(UInt8(memlimit & 0xFF))

			result += salt.bytes

			assert(result.count == Int(DerivedKey.SizeOfPublicParametersInBytes))

			return result
		}

		/**
			Extract the public parameters from a byte array. The size of the
			byte array has to be at least `SizeOfPublicParametersInBytes`. The
			public parameters are extracted from the beginning of the byte
			array.

			- parameters:
				- bytes: An array containing serialized public parameters at the
					beginning.

			- returns: A tuple consisting of the salt, the complexity limit, and
				the memory limit used for deriving the key. `nil` is returned if
				the byte sequence cannot be deserialized.
		*/
		public static func extractPublicParameters(bytes: Bytes) -> (Salt, ComplexityLimit, MemoryLimit)? {
			guard DerivedKey.SizeOfPublicParametersInBytes <= UInt32(bytes.count) else {
				return nil
			}

			let opslimit = (UInt32(bytes[0]) << 24) + (UInt32(bytes[1]) << 16) + (UInt32(bytes[2]) << 8) + UInt32(bytes[3])
			let memlimit = (UInt32(bytes[4]) << 24) + (UInt32(bytes[5]) << 16) + (UInt32(bytes[6]) << 8) + UInt32(bytes[7])
			let saltBytes = Bytes(bytes[8..<(8 + Int(Salt.SizeInBytes))])
			guard let salt = Salt(bytes: saltBytes) else {
				return nil
			}

			guard let complexity = ComplexityLimit(value: Int(opslimit)) else {
				return nil
			}

			guard let memory = MemoryLimit(value: Int(memlimit)) else {
				return nil
			}

			return (salt, complexity, memory)
		}

		/**
			Construct a derived key with an expected size. The actual key is not
			initialized, but the public parameters are stored already.

			This is used if the parameters are known, but the key has not been
			derived, yet.

			- parameters:
				- sizeInBytes: The size of the derived key in bytes.
				- salt: The salt that will be used for deriving the key.
				- complexityLimit: The complexity limit that will be used for
					deriving the key.
				- memoryLimit: The memory limit that will be used for deriving
					the key.

			- returns: `nil` if the size of the key is invalid.
		*/
		fileprivate init?(sizeInBytes: UInt32, salt: Salt, complexityLimit: ComplexityLimit, memoryLimit: MemoryLimit) {
			guard DerivedKey.MinimumSizeInBytes <= sizeInBytes else { return nil }
			guard sizeInBytes <= DerivedKey.MaximumSizeInBytes else { return nil }

			self.salt = salt
			self.complexityLimit = complexityLimit
			self.memoryLimit = memoryLimit

			super.init(sizeInBytes: sizeInBytes, initialize: false)
		}
	}

	/**
		The password bytes in secure memory.
	*/
	let bytes: KeyMaterial

	/**
		The password size in bytes.
	*/
	var sizeInBytes: UInt32 {
		return bytes.sizeInBytes
	}

	/**
		Initializes a password from a given string with a given encoding.

		- parameters:
			- password: The password string, e.g., as entered by the user.
			- encoding: The encoding of the `password` string.
	*/
	public init?(_ password: String, using encoding: String.Encoding = .utf8) {
		guard let passwordData = password.data(using: encoding) else {
			// Invalid encoding
			return nil
		}

		var passwordBytes = Bytes(passwordData)
		self.bytes = KeyMaterial(bytes: &passwordBytes)!
	}

	/**
		Hashes a password for securely storing it on disk or in a database for
		the purpose of authenticating a user.

		- warning:
			Do not change the complexity limits unless it is required, due to
			device limits or negative performance impact. Please refer to the
			[Guidelines for choosing the parameters](https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html#guidelines-for-choosing-the-parameters).

		- parameters:
			- complexity: The CPU load required.
			- memory: The amount of memory required.

		- returns: The hashed password, `nil` if something went wrong.

		- see: `HashedPassword`
	*/
	public func hash(complexity: ComplexityLimit = .high, memory: MemoryLimit = .high) -> HashedPassword? {

		let optionalHashedPassword = bytes.withUnsafeBytes {
			passwordBytesPtr in

			return sodium.pwhash.storableString(
				password: passwordBytesPtr,
				passwordSizeInBytes: UInt64(sizeInBytes),
				opslimit: complexity.sodiumValue,
				memlimit: memory.sodiumValue
			)
		}

		guard let hashedPassword = optionalHashedPassword else { return nil }

		return HashedPassword(hashedPassword)
	}

	/**
		Checks if this password authenticates a hashed password.

		- parameters:
			- hashedPassword: The hashed password.

		- returns: `true` if this password authenticates the hashed password.

		- see: `HashedPassword.isVerified(by:)`
	*/
	public func verifies(_ hashedPassword: HashedPassword) -> Bool {
		return bytes.withUnsafeBytes {
			bytesPtr in

			return sodium.pwhash.isVerifying(
				storableString: hashedPassword.string,
				password: bytesPtr,
				passwordSizeInBytes: UInt64(sizeInBytes)
			)
		}
	}

	/**
		Derive a cryptographic key for a given password.

		- parameters:
			- sizeInBytes: The size of the derived key in bytes.
			- salt: The salt that will be used for deriving the key.
			- complexityLimit: The complexity limit that will be used for
				deriving the key.
			- memoryLimit: The memory limit that will be used for deriving
				the key.
	*/
	public func derive(sizeInBytes: UInt32, complexity: ComplexityLimit = .high, memory: MemoryLimit = .high, salt: Salt = Salt()) -> DerivedKey? {
		guard let derivedKey = DerivedKey(sizeInBytes: sizeInBytes, salt: salt, complexityLimit: complexity, memoryLimit: memory) else {
			return nil
		}

		derivedKey.withUnsafeMutableBytes {
			derivedKeyPtr in

			bytes.withUnsafeBytes() {
				passwordBytesPtr in

				sodium.pwhash.derive(
					key: derivedKeyPtr,
					sizeInBytes: UInt64(sizeInBytes),
					from: passwordBytesPtr,
					passwordSizeInBytes: UInt64(bytes.sizeInBytes),
					salt: salt.bytes,
					opslimit: UInt64(complexity.sodiumValue),
					memlimit: memory.sodiumValue
				)
			}
		}

		return derivedKey
	}

}

extension Password: Equatable {
	/**
		Compares two passwords in constant time regardless of their length. This
		is done by calculating a hash (in sense of a fingerprint not in sense of
		a hashed password used for storage) on the password and comparing the
		hash values (which are of equal length) in constant time.

		- parameters:
			- lhs: A password.
			- rhs: Another password.

		- returns: `true` if the passwords are equal.
	*/
	public static func ==(lhs: Password, rhs: Password) -> Bool {
		return lhs.bytes.isFingerprintEqual(to: rhs.bytes)
	}
}
