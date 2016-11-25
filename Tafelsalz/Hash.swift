import libsodium

public class Hash {

	/**
		- warning:
			Values for `enum`s can only be assigned as literals. Due to this
			limitation it is not possible to detect differences to the values
			defined in `libsodium` at compile time. Validation is performed at
			runtime and during tests.

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
			defined in `libsodium` at compile time. Validation is performed at
			runtime and during tests.

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
			defined in `libsodium` at compile time. Validation is performed at
			runtime and during tests.

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

	/// - see: `libsodium.crypto_pwhash_alg_default()`
	static let DefaultPasswordHashingAlgorithm = PasswordHashingAlgorithm.Argon2i_v13

	// For additional integrity/sanity checks that are necessary due to compiler
	// or language limitations.

	static let ExpectedMemoryLimitInBytes_Interactive = PInt(libsodium.crypto_pwhash_memlimit_interactive())
	static let ExpectedMemoryLimitInBytes_Moderate = PInt(libsodium.crypto_pwhash_memlimit_moderate())
	static let ExpectedMemoryLimitInBytes_Sensitive = PInt(libsodium.crypto_pwhash_memlimit_sensitive())

	static let ExpectedComplexityLimit_Interactive = PInt(libsodium.crypto_pwhash_opslimit_interactive())
	static let ExpectedComplexityLimit_Moderate = PInt(libsodium.crypto_pwhash_opslimit_moderate())
	static let ExpectedComplexityLimit_Sensitive = PInt(libsodium.crypto_pwhash_opslimit_sensitive())

	static let ExpectedPasswordHashingAlgorithm_Argon2i_v13 = PInt(libsodium.crypto_pwhash_alg_argon2i13())
	static let ExpectedPasswordHashingAlgorithm_Default = PInt(libsodium.crypto_pwhash_alg_default())

	static func memoryLimitsAreSane() -> Bool {
		return MemoryLimitInBytes.Interactive.rawValue == ExpectedMemoryLimitInBytes_Interactive
			&& MemoryLimitInBytes.Moderate.rawValue == ExpectedMemoryLimitInBytes_Moderate
			&& MemoryLimitInBytes.Sensitive.rawValue == ExpectedMemoryLimitInBytes_Sensitive
	}

	static func complexityLimitsAreSane() -> Bool {
		return ComplexityLimit.Interactive.rawValue == ExpectedComplexityLimit_Interactive
			&& ComplexityLimit.Moderate.rawValue == ExpectedComplexityLimit_Moderate
			&& ComplexityLimit.Sensitive.rawValue == ExpectedComplexityLimit_Sensitive
	}

	static func limitsAreSane() -> Bool {
		return memoryLimitsAreSane() && complexityLimitsAreSane()
	}

	static func passwordHashingAlgorithmValuesAreSane() -> Bool {
		return PasswordHashingAlgorithm.Argon2i_v13.rawValue == ExpectedPasswordHashingAlgorithm_Argon2i_v13
			&& DefaultPasswordHashingAlgorithm.rawValue == ExpectedPasswordHashingAlgorithm_Default
			&& DefaultPasswordHashingAlgorithm == PasswordHashingAlgorithm.Argon2i_v13
	}

	static func mappedValuesAreSane() -> Bool {
		return limitsAreSane() && passwordHashingAlgorithmValuesAreSane()
	}

	public let bytes: Data
	public let salt: Salt

	public init?(withConfidentialValue value: Data, andOutputLengthInBytes outputLength: PInt, andSalt salt: Salt) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard Hash.mappedValuesAreSane() else {
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

		guard Hash.mappedValuesAreSane() else {
			return nil
		}

		guard let salt = Salt() else {
			return nil
		}

		self.init(withConfidentialValue: value, andOutputLengthInBytes: outputLength, andSalt: salt)
	}
}
