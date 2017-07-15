import libsodium

public class SecretBox {

	public class SecretKey: KeyMaterial {
		public static let SizeInBytes = PInt(libsodium.crypto_secretbox_keybytes())

		public init?() {
			super.init(sizeInBytes: SecretKey.SizeInBytes, initialize: false)

			self.withUnsafeMutableBytes {
				bytesPtr in

				libsodium.crypto_secretbox_keygen(bytesPtr)
			}
		}

		public override init?(bytes: inout Data) {
			guard PInt(bytes.count) == SecretKey.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	public class Nonce: KeyMaterial {
		public static let SizeInBytes = PInt(libsodium.crypto_secretbox_noncebytes())

		public init?() {
			super.init(sizeInBytes: Nonce.SizeInBytes)
		}

		public override init?(bytes: inout Data) {
			guard PInt(bytes.count) == Nonce.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	public class AuthenticationCode: KeyMaterial {
		public static let SizeInBytes = PInt(libsodium.crypto_secretbox_macbytes())

		public override init?(bytes: inout Data) {
			guard PInt(bytes.count) == AuthenticationCode.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	public struct AuthenticatedCiphertext: EncryptedData {
		public static let PrefixSizeInBytes = Nonce.SizeInBytes + AuthenticationCode.SizeInBytes

		public let nonce: Nonce
		public let authenticationCode: AuthenticationCode
		public let ciphertext: Ciphertext

		public var sizeInBytes: PInt {
			get {
				return AuthenticatedCiphertext.PrefixSizeInBytes + ciphertext.sizeInBytes
			}
		}

		public var bytes: Data {
			get {
				var result = Data()
				nonce.withUnsafeBytes { result.append($0, count: Int(nonce.sizeInBytes)) }
				authenticationCode.withUnsafeBytes { result.append($0, count: Int(authenticationCode.sizeInBytes)) }
				result.append(ciphertext.bytes)
				return result
			}
		}

		public init(nonce: Nonce, authenticationCode: AuthenticationCode, ciphertext: Ciphertext) {
			self.nonce = nonce
			self.authenticationCode = authenticationCode
			self.ciphertext = ciphertext
		}

		public init?(bytes: Data) {
			guard bytes.count > Int(AuthenticatedCiphertext.PrefixSizeInBytes) else {
				return nil
			}

			var nonceBytes = bytes.subdata(in: 0..<Int(Nonce.SizeInBytes))

			guard let nonce = Nonce(bytes: &nonceBytes) else {
				return nil
			}

			var mac = bytes.subdata(in: Int(Nonce.SizeInBytes)..<Int(AuthenticatedCiphertext.PrefixSizeInBytes))

			guard let authenticationCode = AuthenticationCode(bytes: &mac) else {
				return nil
			}

			self.nonce = nonce
			self.authenticationCode = authenticationCode
			self.ciphertext = Ciphertext(bytes.subdata(in: Int(AuthenticatedCiphertext.PrefixSizeInBytes)..<bytes.count))
		}
	}

	private let secretKey: SecretKey

	public init?(secretKey: SecretKey) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}
		self.secretKey = secretKey
	}

	public convenience init?(persona: Persona) {
		guard let secretKey = persona.secret() else {
			return nil
		}
		self.init(secretKey: secretKey)
	}

	public convenience init?() {
		guard let secretKey = SecretKey() else {
			return nil
		}
		self.init(secretKey: secretKey)
	}

	public func encrypt(data plaintext: Data) -> AuthenticatedCiphertext? {
		guard let nonce = Nonce() else {
			return nil
		}

		var ciphertext = Data(count: plaintext.count)
		var mac = Data(count: Int(AuthenticationCode.SizeInBytes))

		let successfullyEncrypted = ciphertext.withUnsafeMutableBytes {
			ciphertextPtr in

			return mac.withUnsafeMutableBytes {
				macPtr in

				return plaintext.withUnsafeBytes {
					plaintextPtr in

					return nonce.withUnsafeBytes {
						noncePtr in

						return secretKey.withUnsafeBytes {
							secretKeyPtr in

							return libsodium.crypto_secretbox_detached(
								ciphertextPtr,
								macPtr,
								plaintextPtr,
								UInt64(plaintext.count),
								noncePtr,
								secretKeyPtr
							) == 0
						}
					}
				}
			}
		}

		guard successfullyEncrypted else {
			return nil
		}

		guard let authenticationCode = AuthenticationCode(bytes: &mac) else {
			return nil
		}

		return AuthenticatedCiphertext(nonce: nonce, authenticationCode: authenticationCode, ciphertext: Ciphertext(ciphertext))
	}

	public func decrypt(data authenticatedCiphertext: AuthenticatedCiphertext) -> Data? {

		var plaintext = Data(count: Int(authenticatedCiphertext.ciphertext.sizeInBytes))

		let successfullyDecrypted = plaintext.withUnsafeMutableBytes {
			plaintextPtr in

			return authenticatedCiphertext.ciphertext.bytes.withUnsafeBytes {
				ciphertextPtr in

				return authenticatedCiphertext.authenticationCode.withUnsafeBytes {
					macPtr in

					return authenticatedCiphertext.nonce.withUnsafeBytes {
						noncePtr in

						return self.secretKey.withUnsafeBytes {
							secretKeyPtr in

							return libsodium.crypto_secretbox_open_detached(
								plaintextPtr,
								ciphertextPtr,
								macPtr,
								UInt64(authenticatedCiphertext.ciphertext.sizeInBytes),
								noncePtr,
								secretKeyPtr
							) == 0
						}
					}
				}
			}
		}

		return successfullyDecrypted ? plaintext : nil
	}
}

extension SecretBox.Nonce: Equatable {
	public static func ==(lhs: SecretBox.Nonce, rhs: SecretBox.Nonce) -> Bool {
		return lhs.isEqual(to: rhs)
	}
}

extension SecretBox.AuthenticationCode: Equatable {
	public static func ==(lhs: SecretBox.AuthenticationCode, rhs: SecretBox.AuthenticationCode) -> Bool {
		return lhs.isEqual(to: rhs)
	}
}
