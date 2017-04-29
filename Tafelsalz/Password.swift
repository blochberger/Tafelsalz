import libsodium

public class Password {

	private var bytes: Data

	init?(_ password: String, withEncoding encoding: String.Encoding = .utf8) {

		guard let bytes = password.data(using: encoding) else {
			// Invalid encoding
			return nil
		}

		self.bytes = bytes
	}

	deinit {
		bytes.withUnsafeMutableBytes {
			bytesPtr in

			libsodium.sodium_memzero(bytesPtr, bytes.count)
		}
	}

	public func hash() -> HashedPassword? {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		var hashedPasswordBytes = Data(count: Int(HashedPassword.SizeInBytes))

		let successfullyHashed = hashedPasswordBytes.withUnsafeMutableBytes {
			hashedPasswordBytesPtr in

			return bytes.withUnsafeBytes {
				passwordBytesPtr in

				return libsodium.crypto_pwhash_str(
					hashedPasswordBytesPtr,
					passwordBytesPtr,
					UInt64(bytes.count),
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

	func verifies(_ hashedPassword: HashedPassword) -> Bool {
		return bytes.withUnsafeBytes {
			bytesPtr in

			return hashedPassword.bytes.withUnsafeBytes {
				hashedPasswordBytesPtr in

				return libsodium.crypto_pwhash_str_verify(
					hashedPasswordBytesPtr,
					bytesPtr,
					UInt64(bytes.count)
				) == 0
			}
		}
	}

	// <#TODO#> Offer method for securely persisting password in system Keychain.
}
