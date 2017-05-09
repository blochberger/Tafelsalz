import libsodium

public class Password: KeyMaterial {
	public init?(_ password: String, using encoding: String.Encoding = .utf8) {
		guard var bytes = password.data(using: encoding) else {
			// Invalid encoding
			return nil
		}

		super.init(bytes: &bytes)
	}

	public func hash() -> HashedPassword? {
		var hashedPasswordBytes = Data(count: Int(HashedPassword.SizeInBytes))

		let successfullyHashed = hashedPasswordBytes.withUnsafeMutableBytes {
			hashedPasswordBytesPtr in

			return withUnsafeBytes {
				passwordBytesPtr in

				return libsodium.crypto_pwhash_str(
					hashedPasswordBytesPtr,
					passwordBytesPtr,
					UInt64(sizeInBytes),
					UInt64(libsodium.crypto_pwhash_opslimit_sensitive()),
					libsodium.crypto_pwhash_memlimit_sensitive()
				) == 0
			}
		}

		guard successfullyHashed else {
			return nil
		}

		return HashedPassword(hashedPasswordBytes)
	}

	public func verifies(_ hashedPassword: HashedPassword) -> Bool {
		return withUnsafeBytes {
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
