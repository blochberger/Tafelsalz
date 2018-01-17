/**
	A class that can be used for exchanging keys between two parties on an
	adverserial channel.

	### Example

	```swift
	let alice = KeyExchange(side: .client)
	let bob = KeyExchange(side: .server)

	let alicesSessionKey = alice.sessionKey(for: bob.publicKey)
	let bobsSessionKey = bob.sessionKey(for: alice.publicKey)

	// alicesSessionKey == bobsSessionKey
	```
*/
public class KeyExchange {

	/**
		The side of the key exchange.
	*/
	public enum Side {

		/**
			This denotes the client side of the key exchange.
		*/
		case client

		/**
			This denotes the server side of the key exchange.
		*/
		case server
	}

	/**
		The secret key of key exchange.
	*/
	private class SecretKey: KeyMaterial {

		/**
			The size of the secret key in bytes.
		*/
		static let SizeInBytes = UInt32(sodium.kx.secretKeySizeInBytes)

		/**
			Creates a secret key from other key material.

			- precondition:
				`other.sizeInBytes` = `SizeInBytes`

			- parameters:
				- other: The other key material.
		*/
		override init(_ other: KeyMaterial) {
			precondition(other.sizeInBytes == SecretKey.SizeInBytes)

			super.init(other)
		}

	}

	public class PublicKey: KeyMaterial {

		/**
			The size of the public key in bytes.
		*/
		public static let SizeInBytes = UInt32(sodium.kx.publicKeySizeInBytes)

		/**
			Creates a public key from other key material.

			- precondition:
				`other.sizeInBytes` = `SizeInBytes`

			- parameters:
				- other: The other key material.
		*/
		override init(_ other: KeyMaterial) {
			precondition(other.sizeInBytes == SecretKey.SizeInBytes)

			super.init(other)
		}

		/**
			Restores a public key from a given byte array. The byte array is
			copied to a secure location and overwritten with zeroes to avoid the
			key being compromised in memory.

			- warning:
				Do not initialize new keys with this function. If you need a new
				key, use `KeyExchange.init()` instead. This initializer is only
				to restore public keys that were persisted or transmitted.

			- parameters:
				- bytes: A public key.
		*/
		public override init?(bytes: inout Data) {
			guard UInt32(bytes.count) == SecretKey.SizeInBytes else {
				return nil
			}

			super.init(bytes: &bytes)
		}

	}

	public class SessionKey: KeyMaterial {

		/**
			The size of the session key in bytes.
		*/
		static let SizeInBytes = UInt32(sodium.kx.sessionKeySizeInBytes)

		/**
			Creates a session key from other key material.

			- precondition:
				`other.sizeInBytes` = `SizeInBytes`

			- parameters:
				- other: The other key material.
		*/
		override init(_ other: KeyMaterial) {
			precondition(other.sizeInBytes == SessionKey.SizeInBytes)

			super.init(other)
		}

	}

	/**
		A session key pair.
	*/
	public struct SessionKeyPair {

		/**
			This session key should be used by the client to receive data from
			the server and by the server to receive data from the client.
		*/
		public let rx: SessionKey

		/**
			This session key should be used by the client to send data to the
			server and by the server to send data to the client.
		*/
		public let tx: SessionKey

	}

	/**
		The side of the key exchange.
	*/
	public let side: Side

	/**
		The public key.
	*/
	public let publicKey: PublicKey

	/**
		The secret key.
	*/
	private let secretKey: SecretKey

	/**
		Initializes the local part of a key exchange.

		- parameters:
			- side: The side of the key exchange.
	*/
	public init(side: Side) {
		let publicKey = KeyMaterial(sizeInBytes: PublicKey.SizeInBytes, initialize: false)
		let secretKey = KeyMaterial(sizeInBytes: SecretKey.SizeInBytes, initialize: false)

		publicKey.withUnsafeMutableBytes { publicKeyPtr in
			secretKey.withUnsafeMutableBytes { secretKeyPtr in
				sodium.kx.keypair(publicKeyPtr: publicKeyPtr, secretKeyPtr: secretKeyPtr)
			}
		}

		self.side = side
		self.publicKey = PublicKey(publicKey)
		self.secretKey = SecretKey(secretKey)
	}

	/**
		Exchanges a session key pair with another party.

		- note:
			If this party is the client side, the other party needs to be the
			server side vice versa.

		- parameters:
			- otherPublicKey: The public key of the other party.

		- returns:
			The session key pair on success and `nil` if the public key of the
			other party is not acceptable.
	*/
	public func sessionKeys(for otherPublicKey: PublicKey) -> SessionKeyPair? {
		let rx = KeyMaterial(sizeInBytes: SessionKey.SizeInBytes, initialize: false)
		let tx = KeyMaterial(sizeInBytes: SessionKey.SizeInBytes, initialize: false)

		let status = rx.withUnsafeMutableBytes {
			(rxPtr: UnsafeMutablePointer<UInt8>) -> Int32 in

			return tx.withUnsafeMutableBytes {
				(txPtr: UnsafeMutablePointer<UInt8>) -> Int32 in

				return otherPublicKey.withUnsafeBytes {
					(otherPublicKeyPtr: UnsafePointer<UInt8>) -> Int32 in

					return publicKey.withUnsafeBytes {
						(publicKeyPtr: UnsafePointer<UInt8>) -> Int32 in

						return secretKey.withUnsafeBytes {
							(secretKeyPtr: UnsafePointer<UInt8>) -> Int32 in

							switch side {
								case .client:
									return sodium.kx.client_session_keys(
										rxPtr: rxPtr,
										txPtr: txPtr,
										clientPk: publicKeyPtr,
										clientSk: secretKeyPtr,
										serverPk: otherPublicKeyPtr
									)
								case .server:
									return sodium.kx.server_session_keys(
										rxPtr: rxPtr,
										txPtr: txPtr,
										serverPk: publicKeyPtr,
										serverSk: secretKeyPtr,
										clientPk: otherPublicKeyPtr
									)
							}
						}
					}
				}
			}
		}

		guard status == 0 else {
			return nil
		}

		return SessionKeyPair(rx: SessionKey(rx), tx: SessionKey(tx))
	}

	/**
		Exchanges a single key with another party.

		- note:
			If this party is the client side, the other party needs to be the
			server side vice versa.

		- parameters:
			- otherPublicKey: The public key of the other party.

		- returns:
			The session key on success and `nil` if the public key of the other
			party is not acceptable.
	*/
	public func sessionKey(for otherPublicKey: PublicKey) -> SessionKey? {
		guard let keys = sessionKeys(for: otherPublicKey) else {
			return nil
		}

		switch side {
			case .client:
				return keys.rx
			case .server:
				return keys.tx
		}
	}

}
