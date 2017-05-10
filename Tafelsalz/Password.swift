import libsodium

public class Password {

	public enum ComplexityLimit {
		case medium
		case high
		case veryHigh
	}

	public enum MemoryLimit {
		case medium
		case high
		case veryHigh
	}

	private static func sodiumValue(_ value: ComplexityLimit) -> Int {
		switch value {
			case .medium:
				return libsodium.crypto_pwhash_opslimit_interactive()
			case .high:
				return libsodium.crypto_pwhash_opslimit_moderate()
			case .veryHigh:
				return libsodium.crypto_pwhash_opslimit_sensitive()
		}
	}

	private static func sodiumValue(_ value: MemoryLimit) -> Int {
		switch value {
		case .medium:
			return libsodium.crypto_pwhash_memlimit_interactive()
		case .high:
			return libsodium.crypto_pwhash_memlimit_moderate()
		case .veryHigh:
			return libsodium.crypto_pwhash_memlimit_sensitive()
		}
	}

	let bytes: KeyMaterial

	var sizeInBytes: PInt {
		get {
			return bytes.sizeInBytes
		}
	}

	public init?(_ password: String, using encoding: String.Encoding = .utf8) {
		guard var passwordBytes = password.data(using: encoding) else {
			// Invalid encoding
			return nil
		}

		guard let bytes = KeyMaterial(bytes: &passwordBytes) else {
			return nil
		}

		self.bytes = bytes
	}

	public func hash(complexity: ComplexityLimit = .high, memory: MemoryLimit = .high) -> HashedPassword? {
		var hashedPasswordBytes = Data(count: Int(HashedPassword.SizeInBytes))

		let successfullyHashed = hashedPasswordBytes.withUnsafeMutableBytes {
			hashedPasswordBytesPtr in

			return bytes.withUnsafeBytes {
				passwordBytesPtr in

				return libsodium.crypto_pwhash_str(
					hashedPasswordBytesPtr,
					passwordBytesPtr,
					UInt64(sizeInBytes),
					UInt64(Password.sodiumValue(complexity)),
					Password.sodiumValue(memory)
				) == 0
			}
		}

		guard successfullyHashed else {
			return nil
		}

		return HashedPassword(hashedPasswordBytes)
	}

	public func verifies(_ hashedPassword: HashedPassword) -> Bool {
		return bytes.withUnsafeBytes {
			bytesPtr in

			return hashedPassword.bytes.withUnsafeBytes {
				hashedPasswordBytesPtr in

				return libsodium.crypto_pwhash_str_verify(
					hashedPasswordBytesPtr,
					bytesPtr,
					UInt64(sizeInBytes)
				) == 0
			}
		}
	}
}

extension Password: Equatable {
	public static func ==(lhs: Password, rhs: Password) -> Bool {
		return lhs.bytes.isFingerprintEqual(to: rhs.bytes)
	}
}
