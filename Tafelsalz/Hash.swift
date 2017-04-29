import libsodium

public class Hash {

	/**
		- warning:
			Values for `enum`s can only be assigned as literals. Due to this
			limitation it is not possible to detect differences to the values
			defined in `libsodium` at compile time. Validation is performed by
			tests.

			The actual values are defined in `libsodium/crypto_pwhash_argon2i.h`
	*/
	enum MemoryLimitInBytes: PInt {
		/// - see: `libsodium.crypto_pwhash_memlimit_interactive()`
		case Interactive = 33554432
		/// - see: `libsodium.crypto_pwhash_memlimit_moderate()`
		case Moderate = 134217728
		/// - see: `libsodium.crypto_pwhash_memlimit_sensitive()`
		case Sensitive = 536870912
	}

	/**
		- warning:
			Values for `enum`s can only be assigned as literals. Due to this
			limitation it is not possible to detect differences to the values
			defined in `libsodium` at compile time. Validation is performed by
			tests.

			The actual values are defined in `libsodium/crypto_pwhash_argon2i.h`
	*/
	enum ComplexityLimit: PInt {
		/// - see: `libsodium.crypto_pwhash_opslimit_interactive()`
		case Interactive = 4
		/// - see: `libsodium.crypto_pwhash_opslimit_moderate()`
		case Moderate = 6
		/// - see: `libsodium.crypto_pwhash_opslimit_sensitive()`
		case Sensitive = 8
	}

	/**
		- warning:
			Values for `enum`s can only be assigned as literals. Due to this
			limitation it is not possible to detect differences to the values
			defined in `libsodium` at compile time. Validation is performed by
			tests.

			The actual values are defined in `libsodium/crypto_pwhash_argon2i.h`
	*/
	enum PasswordHashingAlgorithm: PInt {
		/// - see: `libsodium.crypto_pwhash_alg_argon2i13()`
		case Argon2i_v13 = 1
	}

	public struct Salt {
		static let SizeInBytes = PInt(libsodium.crypto_pwhash_saltbytes())

		public let bytes: Data

		/**
			Generates a new cryptographically secure random salt.
		*/
		public init?() {
			guard let random = Random() else {
				return nil
			}
			self.bytes = random.bytes(count: Salt.SizeInBytes)
		}
	}

	static let DefaultPasswordHashingAlgorithm = PasswordHashingAlgorithm(rawValue: PInt(libsodium.crypto_pwhash_alg_default()))!

	public let bytes: Data
	public let salt: Salt

	public init?(withConfidentialValue value: Data, andOutputLengthInBytes outputLength: PInt, andSalt salt: Salt) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		var hash = Data(count: Int(outputLength))

		let successfullyHashed = hash.withUnsafeMutableBytes {
			hashPtr in

			return value.withUnsafeBytes {
				valuePtr in

				return salt.bytes.withUnsafeBytes {
					saltPtr in

					return libsodium.crypto_pwhash(
						hashPtr,
						UInt64(outputLength),
						valuePtr,
						UInt64(value.count),
						saltPtr,
						UInt64(ComplexityLimit.Sensitive.rawValue),
						Int(MemoryLimitInBytes.Sensitive.rawValue),
						Int32(Hash.DefaultPasswordHashingAlgorithm.rawValue)
					) == 0;
				}
			}

		}

		guard successfullyHashed else {
			return nil
		}

		self.bytes = hash
		self.salt = salt
	}

	public convenience init?(withConfidentialValue value: Data, andOutputLengthInBytes outputLength: PInt) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard let salt = Salt() else {
			return nil
		}

		self.init(withConfidentialValue: value, andOutputLengthInBytes: outputLength, andSalt: salt)
	}
}
