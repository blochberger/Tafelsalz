/**
	This class can be used to encrypt/decrypt data based on a shared secret
	(symmetric key).

	## Example

	### Ephemeral Keys

	An ephemeral key is destroyed once the `SecretBox` is destroyed. There is no
	way to recover it unless otherwise persisted. This can be used for keys that
	should only reside in memory, e.g., if they were shared between multiple
	parties.

	```swift
	let secretBox = SecretBox()
	let plaintext = Data("Hello, World!".utf8)
	let ciphertext = secretBox.encrypt(data: plaintext)
	let decrypted = secretBox.decrypt(data: ciphertext)!
	```

	### Persisted Keys

	Persisted keys will be stored in and loaded from the system's Keychain
	automatically. This is useful for encrypting data for oneself, e.g., if you
	want to store encrypted files in a public document storage, such as Dropbox.

	```swift
	// Create a persona
	let alice = Persona(uniqueName: "Alice")

	// Once a secret of that persona is used, it will be persisted in the
	// system's Keychain.
	let secretBox = SecretBox(persona: alice)!

	// Use your SecretBox as usual
	let plaintext = Data("Hello, World!".utf8)
	let ciphertext = secretBox.encrypt(data: plaintext)
	let decrypted = secretBox.decrypt(data: ciphertext)!

	// Forget the persona and remove all related Keychain entries
	try! Persona.forget(alice)
	```
*/
public class SecretBox {

	/**
		A class for secret keys that can be used by the `SecretBox`.
	*/
	public class SecretKey: KeyMaterial {
		/**
			The size of the secret key in bytes.
		*/
		public static let SizeInBytes = UInt32(sodium.secretbox.sizeOfKeyInBytes)

		/**
			Generates a new secret key.
		*/
		public init() {
			super.init(sizeInBytes: SecretKey.SizeInBytes, initialize: false)

			self.withUnsafeMutableBytes {
				bytesPtr in

				sodium.secretbox.keygen(bytesPtr)
			}
		}

		/**
			Creates a secret key from other key material.

			- precondition:
				`other.sizeInBytes` = `SizeInBytes`
		
			- parameters:
				- other: The other key material.
		*/
		public override init(_ other: KeyMaterial) {
			precondition(other.sizeInBytes == SecretKey.SizeInBytes)

			super.init(other)
		}

		/**
			Restores a secret key from a given byte array. The byte array is
			copied to a secure location and overwritten with zeroes to avoid the
			key being compromised in memory.

			- warning:
				Do not initialize new keys with this function. If you need a new
				key, use `init?()` instead. This initializer is only to restore
				secret keys that were persisted.

			- parameters:
				- bytes: A secret key.
		*/
		public override init?(bytes: inout Bytes) {
			guard UInt32(bytes.count) == SecretKey.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	/**
		This class represents a nonce (number used once) that is required for
		indeterministically encrypting a given message.
	*/
	public class Nonce: KeyMaterial {
		/**
			The size of the nonce in bytes.
		*/
		public static let SizeInBytes = UInt32(sodium.secretbox.sizeOfNonceInBytes)

		/**
			Creates a new random nonce.
		*/
		public init() {
			super.init(sizeInBytes: Nonce.SizeInBytes)
		}

		/**
			Restores a nonce from a byte array. The byte array is copied to a
			secure location and overwritten with zeroes to avoid the nonce being
			compromised in memory. The nonce itself is not a secret value, but
			access in other contexts is not necessary.

			- warning:
				Do not use this function to create nonces. This initializer is
				only intended to restore a nonce that was persisted.

			- parameters:
				- bytes: The nonce.
		*/
		public override init?(bytes: inout Bytes) {
			guard UInt32(bytes.count) == Nonce.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	/**
		This class represents a message authentication code to verify the
		integrity of encrypted messages.
	*/
	public class AuthenticationCode: KeyMaterial {
		/**
			The size of the authentication code in bytes.
		*/
		public static let SizeInBytes = UInt32(sodium.secretbox.sizeOfMacInBytes)

		/**
			Restore a authentication code from a byte array. Authentication
			codes are generated when encrypting a message. This initializer is
			for restoring an authentication code if it was persisted. The byte
			array is copied to a secure location and overwritten with zeroes to
			avoid the authentication code being compromised in memory. The
			authentication code itself is not a secret value, but access in
			other contexts is not necessary.

			- parameters:
				- bytes: The message authentication code.
		*/
		public override init?(bytes: inout Bytes) {
			guard UInt32(bytes.count) == AuthenticationCode.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}
	}

	/**
		This class represents an authenticated ciphertext, which is an encrypted
		message including the nonce used for indeterministic encryption and a
		message authentication code for verifying the integrity of the encrypted
		message.
	*/
	public struct AuthenticatedCiphertext: EncryptedData {
		/**
			The size of the authentication code and the nonce in bytes. For the
			full size in bytes of an authenticated ciphertext see `sizeInBytes`.
		*/
		public static let PrefixSizeInBytes = Nonce.SizeInBytes + AuthenticationCode.SizeInBytes

		/**
			The nonce.
		*/
		public let nonce: Nonce

		/**
			The message authentication code.
		*/
		public let authenticationCode: AuthenticationCode

		/**
			The encrypted message.
		*/
		public let ciphertext: Ciphertext

		/**
			The size of the authenticated ciphertext in bytes. This includes the
			nonce, authentication code, and the encryped message.
		*/
		public var sizeInBytes: UInt32 {
			get {
				return AuthenticatedCiphertext.PrefixSizeInBytes + ciphertext.sizeInBytes
			}
		}

		/**
			The authenticated ciphertext. This includes the nonce,
			authentication code, and the encryped message.
		*/
		public var bytes: Bytes {
			return nonce.copyBytes() + authenticationCode.copyBytes() + ciphertext.bytes
		}

		/**
			Initializes an authenticated ciphertext.

			- parameters:
				- nonce: The nonce.
				- authenticationCode: The message authentication code.
				- ciphertext: The encrypted message.
		*/
		public init(nonce: Nonce, authenticationCode: AuthenticationCode, ciphertext: Ciphertext) {
			self.nonce = nonce
			self.authenticationCode = authenticationCode
			self.ciphertext = ciphertext
		}

		/**
			Inizializes an authenticated ciphertext from a byte array.

			- parameters:
				- bytes: The byte array.
		*/
		public init?(bytes: Bytes) {
			guard bytes.count > Int(AuthenticatedCiphertext.PrefixSizeInBytes) else {
				return nil
			}

			var nonceBytes = bytes[..<Int(Nonce.SizeInBytes)].bytes
			let nonce = Nonce(bytes: &nonceBytes)!

			var mac = bytes[Int(Nonce.SizeInBytes)..<Int(AuthenticatedCiphertext.PrefixSizeInBytes)].bytes
			let authenticationCode = AuthenticationCode(bytes: &mac)!

			self.nonce = nonce
			self.authenticationCode = authenticationCode
			self.ciphertext = Ciphertext(bytes[Int(AuthenticatedCiphertext.PrefixSizeInBytes)...].bytes)
		}
	}

	/**
		The secret key.
	*/
	private let secretKey: SecretKey

	/**
		Initializes a secret box with a given secret key.

		- parameters:
			- secretKey: The secret key.
	*/
	public init(secretKey: SecretKey) {
		self.secretKey = secretKey
	}

	/**
		Initializes a secret box for a given persona. This automatically loads
		secret key for that persona from the system's Keychain.

		- parameters:
			- persona: The persona to which the secret key belongs.
	*/
	public convenience init?(persona: Persona) {
		guard let secretKey = try? persona.secretKey() else {
			return nil
		}
		self.init(secretKey: secretKey)
	}

	/**
		Initializes a secret box with an ephemeral key. The key cannot be
		accessed and will be irrevocably destroyed once the secret box object is
		deleted. Encrypted messages can than no longer be decrypted.
	*/
	public convenience init() {
		let secretKey = SecretKey()
		self.init(secretKey: secretKey)
	}

	/**
		Encrypts a message with a given nonce.

		The message can be decrypted by using `decrypt(authenticatedCiphertext:)`

		- note:
			This function should only be used if you are required to use a
			specific nonce. Usually `encrypt(plaintext:)` should be preferred.

		- parameters:
			- plaintext: The message that should be encrypted.
			- nonce: A nonce (number used once).

		- returns: An authenticated ciphertext containing the encrypted message.
	*/
	public func encrypt(plaintext: Bytes, with nonce: Nonce = Nonce()) -> AuthenticatedCiphertext {
		var macBytes: Bytes
		let ciphertextBytes: Bytes
		(macBytes, ciphertextBytes) = nonce.withUnsafeBytes {
			noncePtr in

			return secretKey.withUnsafeBytes {
				secretKeyPtr in

				return sodium.secretbox.encrypt(plaintext: plaintext, nonce: noncePtr, key: secretKeyPtr)
			}
		}

		let authenticationCode = AuthenticationCode(bytes: &macBytes)!

		return AuthenticatedCiphertext(nonce: nonce, authenticationCode: authenticationCode, ciphertext: Ciphertext(ciphertextBytes))
	}

	/**
		Decrypts an encrypted message.

		A message can be encrypted by using `encrypt(plaintext:)`.

		- parameters:
			- authenticatedCiphertext: The authenticated ciphertext of the
				encrypted message.

		- returns: The decrypted message.
	*/
	public func decrypt(ciphertext authenticatedCiphertext: AuthenticatedCiphertext) -> Bytes? {
		return authenticatedCiphertext.authenticationCode.withUnsafeBytes {
			macPtr in

			return authenticatedCiphertext.nonce.withUnsafeBytes {
				noncePtr in

				return secretKey.withUnsafeBytes {
					secretKeyPtr in

					return sodium.secretbox.decrypt(
						ciphertext: authenticatedCiphertext.ciphertext.bytes,
						mac: macPtr,
						nonce: noncePtr,
						key: secretKeyPtr
					)
				}
			}
		}
	}
}

extension SecretBox.Nonce: Equatable {
	/**
		Compares two nonces in constant time.

		- parameters:
			- lhs: A nonce.
			- rhs: Another nonce.

		- returns: `true` if both nonces are equal.
	*/
	public static func ==(lhs: SecretBox.Nonce, rhs: SecretBox.Nonce) -> Bool {
		return lhs.isEqual(to: rhs)
	}
}

extension SecretBox.AuthenticationCode: Equatable {

	/**
		Compares two message authentication codes in constant time.

		- parameters:
			- lhs: A message authentication code.
			- rhs: Another message authentication code.

		- returns: `true` if both message authentication codes are equal.
	*/
	public static func ==(lhs: SecretBox.AuthenticationCode, rhs: SecretBox.AuthenticationCode) -> Bool {
		return lhs.isEqual(to: rhs)
	}
}
