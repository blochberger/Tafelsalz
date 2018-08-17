import libsodium

/**
	A singleton instance of the `libsodium` wrapper.
*/
let sodium = Sodium()

/**
	The default return value that indicates success of an operation performed
	by `libsodium`.
*/
fileprivate let sSuccess: Int32 = 0

/**
	A wrapper for `libsodium` that on one hand offers convenient access to the
	`libsodium` bindings and on the other hand assures that `libsodium` was
	initialized before actually invoking methods.
*/
struct Sodium {

	/**
		This initializes `libsodium`.

		- see: [`libsodium` Usage](https://download.libsodium.org/doc/usage/)
	*/
	fileprivate init() {
		let sAlreadyInitialized: Int32 = 1
		let sFailure: Int32 = -1

		let status = libsodium.sodium_init()

		guard status != sFailure else {
			fatalError("Failed to initialize libsodium!")
		}

		guard [sSuccess, sAlreadyInitialized].contains(status) else {
			fatalError("Unhandled status: \(status)")
		}
	}

	// MARK: GenericHash

	/**
		Access to the wrapper for generic hashing.
	*/
	let generichash = SodiumGenericHash()

	/**
		A wrapper for generic hashing.
	*/
	struct SodiumGenericHash {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			The default key size in bytes.
		*/
		let defaultKeySizeInBytes = libsodium.crypto_generichash_keybytes()

		/**
			The maximum key size in bytes.
		*/
		let minimumKeySizeInBytes = libsodium.crypto_generichash_keybytes_min()

		/**
			The minimum key size in bytes.
		*/
		let maximumKeySizeInBytes = libsodium.crypto_generichash_keybytes_max()

		/**
			The default output size in bytes.
		*/
		let defaultOutputSizeInBytes = libsodium.crypto_generichash_bytes()

		/**
			The minimum output size in bytes.
		*/
		let minimumOutputSizeInBytes = libsodium.crypto_generichash_bytes_min()

		/**
			The maximum output size in bytes.
		*/
		let maximumOutputSizeInBytes = libsodium.crypto_generichash_bytes_max()

		/**
			Calculates a generic hash for a given memory region.

			- precondition:
				- `minimumOutputSizeInBytes` ≤ `outputSizeInBytes` ≤ `maximumOutputSizeInBytes`
				- 0 ≤ `inputSizeInBytes`
				- 0 ≤ `keySizeInBytes`
				- `key` ≠ `nil` ⇒ `minimumKeySizeInBytes` ≤ `keySizeInBytes` ≤ `maximumKeySizeInBytes`

			- parameters:
				- outputSizeInBytes: The size of the output in bytes.
				- input: A pointer to the memory region that should be hashed.
				- inputSizeInBytes: The size of `input`.
				- key: The key that should be used for keyed hashing.
				- keySizeInBytes: The size of `key`.

			- returns: The hash.
		*/
		func hash(outputSizeInBytes: Int, input: UnsafePointer<UInt8>, inputSizeInBytes: UInt64, key: UnsafePointer<UInt8>? = nil, keySizeInBytes: Int = 0) -> Bytes {
			precondition(minimumOutputSizeInBytes <= outputSizeInBytes)
			precondition(outputSizeInBytes <= maximumOutputSizeInBytes)

			precondition(0 <= inputSizeInBytes)

			precondition(0 <= keySizeInBytes)
			precondition(key == nil || minimumKeySizeInBytes <= keySizeInBytes)
			precondition(key == nil || keySizeInBytes <= maximumKeySizeInBytes)

			var result = Bytes(count: outputSizeInBytes)

			let status = libsodium.crypto_generichash(
				&result,
				outputSizeInBytes,
				input,
				inputSizeInBytes,
				key,
				keySizeInBytes
			)

			guard status == sSuccess else {
				fatalError("Unhandled status: \(status)")
			}

			return result
		}

		/**
			Calculates a generic hash for a given memory region.

			- precondition: 0 ≤ `inputSizeInBytes`

			- parameters:
				- input: A pointer to the memory region that should be hashed.
				- inputSizeInBytes: The size of `input`.

			- returns: The hash.
		*/
		func hash(input: UnsafePointer<UInt8>, inputSizeInBytes: UInt64) -> Bytes {
			return hash(outputSizeInBytes: defaultOutputSizeInBytes, input: input, inputSizeInBytes: inputSizeInBytes)
		}

	}

	// MARK: KeyDerivation

	/**
		Access to the key derivation wrapper.
	*/
	let kdf = SodiumKeyDerivation()

	/**
		A wrapper for key derivation.
	*/
	struct SodiumKeyDerivation {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			The size of the master key in bytes.
		*/
		let masterKeySizeInBytes = libsodium.crypto_kdf_keybytes()

		/**
			The size of a sub key context in bytes.
		*/
		let contextSizeInBytes = libsodium.crypto_kdf_contextbytes()

		/**
			The minimum size of a derived key in bytes.
		*/
		let minimumSubKeySizeInBytes = libsodium.crypto_kdf_bytes_min()

		/**
			The maximum size of a derived key in bytes.
		*/
		let maximumSubKeySizeInBytes = libsodium.crypto_kdf_bytes_max()

		/**
			Generate a master key.
		
			- parameters:
				- pointer: The memory region where the key will be stored.
		*/
		func keygen(_ pointer: UnsafeMutablePointer<UInt8>) {
			libsodium.crypto_kdf_keygen(pointer)
		}

		/**
			Derive a sub key from a given master key.
		
			- precondition:
				- `minimumSubKeySizeInBytes` ≤ `subKeySizeInBytes` ≤ `maximumSubKeySizeInBytes`
				- `context.count` = `contextSizeInBytes`
				- size of `masterKey` = `masterKeySizeInBytes`
		
			- parameters:
				- subKey: The memory region where the sub key should be stored.
				- subKeySizeInBytes: The size of `subKey` in bytes.
				- subKeyId: The ID of the sub key.
				- context: A context.
				- masterKey: The master key.
		*/
		func derive(subKey: UnsafeMutablePointer<UInt8>, subKeySizeInBytes: Int, subKeyId: UInt64, context: Bytes, masterKey: UnsafePointer<UInt8>) {
			precondition(minimumSubKeySizeInBytes <= subKeySizeInBytes)
			precondition(subKeySizeInBytes <= maximumSubKeySizeInBytes)
			precondition(context.count == contextSizeInBytes)

			let status = context.withUnsafeBytes {
				contextPtr in

				return libsodium.crypto_kdf_derive_from_key(
					subKey,
					subKeySizeInBytes,
					subKeyId,
					contextPtr.map(Int8.init),
					masterKey
				)
			}

			guard status == sSuccess else {
				fatalError("Unhandled status code: \(status)")
			}
		}

	}

	// MARK: Key Exchange

	/**
		Access to the wrapper for key exchange.
	*/
	let kx = SodiumKeyExchange()

	/**
		A wrapper for key exchange.
	*/
	struct SodiumKeyExchange {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			The size of the secret key in bytes.
		*/
		let secretKeySizeInBytes = libsodium.crypto_kx_secretkeybytes()

		/**
			The size of the session key in bytes.
		*/
		let sessionKeySizeInBytes = libsodium.crypto_kx_sessionkeybytes()

		/**
			The size of the public key in bytes.
		*/
		let publicKeySizeInBytes = libsodium.crypto_kx_publickeybytes()

		/**
			Generate a keypair that can be used for exchanging keys.

			- parameters:
				- publicKeyPtr: The pointer to where the public key will be
					stored.
				- secretKeyPtr: The pointer to where the secret key will be
					stored.
		*/
		func keypair(publicKeyPtr: UnsafeMutablePointer<UInt8>, secretKeyPtr: UnsafeMutablePointer<UInt8>) {
			libsodium.crypto_kx_keypair(publicKeyPtr, secretKeyPtr)
		}

		/**
			Calculate session keys for the client side.

			- parameters:
				- rxPtr: A pointer to where the session key, that is used to
					receive data from the server, should be stored.
				- txPtr: A pointer to where the session key, that is used to
					send data to the server, should be stored.
				- clientPk: A pointer to the client's public key.
				- clientSk: A pointer to the client's secret key.
				- serverPk: A pointer to the server's public key.

			- returns:
				`0` on success and `-1` if `serverPk` is not acceptible.
		*/
		func client_session_keys(
			rxPtr: UnsafeMutablePointer<UInt8>,
			txPtr: UnsafeMutablePointer<UInt8>,
			clientPk: UnsafePointer<UInt8>,
			clientSk: UnsafePointer<UInt8>,
			serverPk: UnsafePointer<UInt8>
		) -> Int32 {
			return libsodium.crypto_kx_client_session_keys(rxPtr, txPtr, clientPk, clientSk, serverPk)
		}

		/**
			Calculate session keys for the server side.

			- parameters:
				- rxPtr: A pointer to where the session key, that is used to
					receive data from the client, should be stored.
				- txPtr: A pointer to where the session key, that is used to
					sen data to the client, should be stored.
				- serverPk: A pointer to the server's public key.
				- serverSk: A pointer to the server's secret key.
				- clientPk: A pointer to the client's public key.

			- returns:
				`0` on success and `-1` if `clientPk` is not acceptible.
		*/
		func server_session_keys(
			rxPtr: UnsafeMutablePointer<UInt8>,
			txPtr: UnsafeMutablePointer<UInt8>,
			serverPk: UnsafePointer<UInt8>,
			serverSk: UnsafePointer<UInt8>,
			clientPk: UnsafePointer<UInt8>
		) -> Int32 {
			return libsodium.crypto_kx_server_session_keys(rxPtr, txPtr, serverPk, serverSk, clientPk)
		}

	}

	// MARK: Memory

	/**
		Access to the secure memory wrapper.
	*/
	let memory = SodiumMemory()

	/**
		A wrapper for handling secure memory allocations.

		- see: [`libsodium`: Securing memory allocations](https://download.libsodium.org/doc/helpers/memory_management.html)
	*/
	struct SodiumMemory {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			Allocates a guarded memory region of a given size.

			- precondition: 0 ≤ `sizeInBytes`

			- parameters:
				- sizeInBytes: The size of the allocated memory.

			- returns: A pointer to the guarded memory region.
		*/
		func allocate(sizeInBytes: Int) -> UnsafeMutableRawPointer {
			precondition(0 <= sizeInBytes)

			return libsodium.sodium_malloc(sizeInBytes)!
		}

		/**
			Frees a guarded memory region.

			- parameters: 
				- pointer: A pointer to the guarded memory region.
		*/
		func free(_ pointer: UnsafeMutableRawPointer) {
			libsodium.sodium_free(pointer)
		}

		/**
			Wipes a guarded memory region by overwriting it with zeroes.

			- precondition: 0 ≤ `amountInBytes`

			- parameters:
				- pointer: A pointer to the guarded memory region.
				- amountInBytes: The amount of bytes that should be zeroed,
					starting at the beginning of the memory region.
		*/
		func wipe(_ pointer: UnsafeMutableRawPointer, amountInBytes: Int) {
			precondition(0 <= amountInBytes)

			libsodium.sodium_memzero(pointer, amountInBytes)
		}

		/**
			Wipes a byte array by overwriting it with zeroes.

			- parameters:
				- bytes: A byte array.
		*/
		func wipe(_ bytes: inout Bytes) {
			wipe(&bytes, amountInBytes: bytes.count)
		}

		/**
			Compares two guarded memory regions in constant time.

			- precondition: 0 ≤ `amountInBytes`

			- parameters:
				- lhs: A pointer to the guarded memory region.
				- rhs: A pointer to the guarded memory region.
				- amountInBytes: The amount of bytes that should be compared,
					starting at the beginning of the memory region.

			- returns: `true` if both regions are equal up to `amountInBytes`.
		*/
		func areEqual(_ lhs: UnsafeRawPointer, _ rhs: UnsafeRawPointer, amountInBytes: Int) -> Bool {
			precondition(0 <= amountInBytes)

			let sNotEqual: Int32 = -1

			let status = libsodium.sodium_memcmp(lhs, rhs, amountInBytes)

			guard status != sNotEqual else { return false }

			guard status == sSuccess else {
				fatalError("Unhandled status code: \(status)")
			}

			return true
		}

		/**
			Makes a guarded memory region read-only.

			- parameters:
				- pointer: A pointer to the guarded memory region.
		*/
		func make_readonly(_ pointer: UnsafeMutableRawPointer) {
			let status = libsodium.sodium_mprotect_readonly(pointer)

			guard status == sSuccess else {
				fatalError("Unhandled status code: \(status)")
			}
		}

		/**
			Makes a guarded memory region read-writable.

			- parameters:
				- pointer: A pointer to the guarded memory region.
		*/
		func make_readwritable(_ pointer: UnsafeMutableRawPointer) {
			let status = libsodium.sodium_mprotect_readwrite(pointer)

			guard status == sSuccess else {
				fatalError("Unhandled status code: \(status)")
			}
		}

		/**
			Makes a guarded memory region inaccessible.

			- parameters:
				- pointer: A pointer to the guarded memory region.
		*/
		func make_inaccessible(_ pointer: UnsafeMutableRawPointer) {
			let status = libsodium.sodium_mprotect_noaccess(pointer)

			guard status == sSuccess else {
				fatalError("Unhandled status code: \(status)")
			}
		}

	}

	// MARK: PwHash

	/**
		Access to the password hashing wrapper
	*/
	let pwhash = SodiumPasswordHash()

	/**
		A wrapper for password hashing.
	*/
	struct SodiumPasswordHash {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		let opslimit_interactive = libsodium.crypto_pwhash_opslimit_interactive()
		let opslimit_moderate = libsodium.crypto_pwhash_opslimit_moderate()
		let opslimit_sensitive = libsodium.crypto_pwhash_opslimit_sensitive()

		let memlimit_interactive = libsodium.crypto_pwhash_memlimit_interactive()
		let memlimit_moderate = libsodium.crypto_pwhash_memlimit_moderate()
		let memlimit_sensitive = libsodium.crypto_pwhash_memlimit_sensitive()

		/**
			Size of a storable string in bytes.
		*/
		let sizeOfStorableStringInBytes = libsodium.crypto_pwhash_strbytes()

		/**
			Creates a string that can be used for storing user passwords for the
			purpose of authentication.

			- precondition:
				- 0 ≤ `passwordSizeInBytes`
				- `opslimit` ∈ {`opslimit_interactive`, `opslimit_moderate`, `opslimit_sensitive`}
				- `memlimit` ∈ {`memlimit_interactive`, `memlimit_moderate`, `memlimit_sensitive`}

			- parameters:
				- password: A pointer to the password.
				- passwordSizeInBytes: The size of the password.
				- opslimit: Complexity limit for hashing.
				- memlimit: Memory limit for hashing.

			- returns:
				An ASCII-encoded string that can be stored, `nil` on failure.
		*/
		func storableString(password: UnsafePointer<Int8>, passwordSizeInBytes: UInt64, opslimit: Int, memlimit: Int)  -> String? {
			let sFailure: Int32 = -1

			precondition(0 <= passwordSizeInBytes)
			precondition([opslimit_interactive, opslimit_moderate, opslimit_sensitive].contains(opslimit))
			precondition([memlimit_interactive, memlimit_moderate, memlimit_sensitive].contains(memlimit))

			var result = Bytes(count: sizeOfStorableStringInBytes).map(Int8.init)

			let status = libsodium.crypto_pwhash_str(
				&result,
				password,
				passwordSizeInBytes,
				UInt64(opslimit),
				memlimit
			)

			guard status != sFailure else { return nil }

			guard status == sSuccess else {
				fatalError("Unhandled status: \(status)")
			}

			return String.init(bytes: result.map(UInt8.init), encoding: .ascii)!
		}

		/**
			Check if a password is verifying a storable string.

			- precondition:
				- `storableString` is ASCII-encoded
				- 0 ≤ `passwordSizeInBytes`

			- parameters:
				- storableString: The storable string.
				- password: A pointer to the password.
				- passwordSizeInBytes: The size of the password in bytes.

			- returns: `true` if `password` verifies `storableString`.
		*/
		func isVerifying(storableString: String, password: UnsafePointer<Int8>, passwordSizeInBytes: UInt64) -> Bool {
			let sVerificationFailed: Int32 = -1

			precondition(storableString.data(using: .ascii) != nil)
			precondition(0 <= passwordSizeInBytes)

			let status = storableString.data(using: .ascii)!.withUnsafeBytes {
				strPtr in

				return libsodium.crypto_pwhash_str_verify(strPtr, password, passwordSizeInBytes)
			}

			guard status != sVerificationFailed else { return false }

			guard status == sSuccess else {
				fatalError("Unhandled status: \(status)")
			}

			return true
		}
	}

	// MARK: Random

	/**
		Access to the wrapper for secure random byte generation.
	*/
	let random = SodiumRandom()

	/**
		A wrapper for generating random bytes securely.
	*/
	struct SodiumRandom {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			Write random bytes into a memory region.

			- precondition: 0 ≤ `sizeInBytes`

			- parameters:
				- pointer: A pointer to the memory region.
				- sizeInBytes: The amount of bytes that should be written.
		*/
		func bytes(_ pointer: UnsafeMutableRawPointer, sizeInBytes: Int) {
			precondition(0 <= sizeInBytes)

			libsodium.randombytes_buf(pointer, sizeInBytes)
		}

		/**
			Generate a randomly filled byte array.

			- parameters:
				- count: The size of the byte array in bytes.

			- returns: The byte array.
		*/
		func bytes(count: Int) -> Bytes {
			var result = Bytes(count: count)
			bytes(&result, sizeInBytes: count)
			return result
		}

		/**
			Generate a random number.

			- returns: The random number.
		*/
		func number() -> UInt32 {
			return libsodium.randombytes_random()
		}

		/**
			Generates a random number with uniform distribution.

			- parameters:
				- upperBound: The upper bound.

			- returns: A random number between 0 and `upperBound`.
		*/
		func uniform(upperBound: UInt32) -> UInt32 {
			return libsodium.randombytes_uniform(upperBound)
		}

	}

	// MARK: SecretBox

	/**
		Access to the secret box wrapper.
	*/
	let secretbox = SodiumSecretBox()

	/**
		A wrapper for symmetric encryption.
	*/
	struct SodiumSecretBox {

		/**
			The initializer is disabled.
		*/
		fileprivate init() {}

		/**
			The size of the key in bytes.
		*/
		let sizeOfKeyInBytes = libsodium.crypto_secretbox_keybytes()

		/**
			The size of the nonce in bytes.
		*/
		let sizeOfNonceInBytes = libsodium.crypto_secretbox_noncebytes()

		/**
			The size of the message authentication code (MAC) in bytes.
		*/
		let sizeOfMacInBytes = libsodium.crypto_secretbox_macbytes()

		/**
			Generates a new symmetric key.

			- parameters: 
				- pointer: The memory region where the key will be stored.
		*/
		func keygen(_ pointer: UnsafeMutablePointer<UInt8>) {
			libsodium.crypto_secretbox_keygen(pointer)
		}

		/**
			Encrypt data.

			- precondition:
				- size of `nonce` = `sizeOfNonceInBytes`
				- size of `key` = `sizeOfKeyInBytes`

			- postcondition:
				- `result.0.count` = `sizeOfMacInBytes`
				- `result.1.count` = `plaintext.count`

			- parameters:
				- plaintext: The text that should be encrypted.
				- nonce: A pointer to the nonce.
				- key: A pointer to the key.

			- returns: A tuple (MAC, ciphertext).
		*/
		func encrypt(plaintext: Bytes, nonce: UnsafePointer<UInt8>, key: UnsafePointer<UInt8>) -> (Bytes, Bytes) {
			var ciphertext = Bytes(count: plaintext.count)
			var mac = Bytes(count: sizeOfMacInBytes)

			let status = libsodium.crypto_secretbox_detached(
				&ciphertext,
				&mac,
				plaintext,
				UInt64(plaintext.count),
				nonce,
				key
			)

			guard status == sSuccess else {
				fatalError("Unhandled status: \(status)")
			}

			return (mac, ciphertext)
		}

		/**
			Decrypt data.

			- precondition:
				- size of `mac` = `sizeOfMacInBytes`
				- size of `nonce` = `sizeOfNonceInBytes`
				- size of `key` = `sizeOfKeyInBytes`

			- postcondition: `result.count` = `ciphertext.count`

			- parameters:
				- ciphertext: The ciphertext.
				- mac: A pointer to the message authentication code (MAC).
				- nonce: A pointer to the nonce.
				- key: A pointer to the key.

			- returns:
				The plaintext, `nil` if the integrity of the authenticated
				ciphertext could not be verified.
		*/
		func decrypt(ciphertext: Bytes, mac: UnsafePointer<UInt8>, nonce: UnsafePointer<UInt8>, key: UnsafePointer<UInt8>) -> Bytes? {
			let sVerificationFailed: Int32 = -1

			var plaintext = Bytes(count: ciphertext.count)

			let status = libsodium.crypto_secretbox_open_detached(
				&plaintext,
				ciphertext,
				mac,
				UInt64(ciphertext.count),
				nonce,
				key
			)

			guard status != sVerificationFailed else { return nil }

			guard status == sSuccess else {
				fatalError("Unhandled status: \(status)")
			}

			return plaintext
		}

	}

	// MARK: - Padding

	/**
		Add padding to protect message lengths.

		- warning: Padding has to be applied to plaintext before encryption.

		- precondition: 0 < `blockSize`

		- postcondition: `result.count` % `blockSize` = 0

		- parameters:
			- unpadded: The unpadded plaintext bytes.
			- blockSize: The block size in bytes.

		- returns: The padded plaintext bytes.
	*/
	func pad(unpadded: Bytes, blockSize: Int) -> Bytes {
		precondition(0 < blockSize)

		let sBufferTooSmall = -1

		let bufferLength = ((unpadded.count / blockSize) + 1) * blockSize
		var buffer = unpadded + Bytes(count: bufferLength - unpadded.count)
		var paddedLength = 0
		let status = sodium_pad(&paddedLength, &buffer, unpadded.count, blockSize, bufferLength)

		guard status != sBufferTooSmall else {
			fatalError("Reserved buffer is too small.")
		}

		guard status == sSuccess else {
			fatalError("Unhandled status: \(status)")
		}

		return buffer[..<paddedLength].bytes
	}

	/**
		Add padding to protect message lengths.

		- warning: Padding has to be applied to plaintext before encryption.

		- precondition: 0 < `blockSize`

		- postcondition: `result.count` % `blockSize` = 0

		- parameters:
			- unpadded: The unpadded plaintext bytes.
			- blockSize: The block size in bytes.

		- returns: The padded plaintext bytes.
	*/
	func unpad(padded: Bytes, blockSize: Int) -> Bytes? {
		precondition(0 < blockSize)

		let sInvalidPadding = -1

		var unpaddedLength = 0

		let status = sodium_unpad(&unpaddedLength, padded, padded.count, blockSize)

		guard status != sInvalidPadding else {
			return nil
		}

		guard status == sSuccess else {
			fatalError("Unhandled status: \(status)")
		}

		return padded[..<unpaddedLength].bytes
	}

	// MARK: Utilities

	/**
		Converts hex-characters to a byte array.

		- parameters:
			- hex: The string.
			- ignore: A string containing characters that should be ignored,
				e.g., this is useful to ignore the colon if `hex` is "00:11".

		- returns: The byte array.
	*/
	func hex2bin(_ hex: String, ignore: String? = nil) -> Bytes? {
		let hexBytes = hex.utf8Bytes.map(Int8.init)
		let reservedCapacity = hexBytes.count / 2
		var result = Bytes(count: reservedCapacity)
		var bytesWritten: size_t = 0
		let ignoreBytes = ignore?.utf8Bytes.map(Int8.init)

		let status = libsodium.sodium_hex2bin(
			&result,
			reservedCapacity,
			hexBytes,
			hexBytes.count,
			ignoreBytes,
			&bytesWritten,
			nil
		)

		guard status == sSuccess else {
			return nil
		}

		return result[..<bytesWritten].bytes
	}

	/**
		Converts a byte array to a hex-encoded string.

		- parameters:
			- bin: The byte array.

		- returns: The hex-encoded string.
	*/
	func bin2hex(_ bin: Bytes) -> String {
		let sizeOfResultInBytes = bin.count * 2 + 1
		var result = Bytes(count: sizeOfResultInBytes).map(Int8.init)

		libsodium.sodium_bin2hex(
			&result,
			sizeOfResultInBytes,
			bin,
			bin.count
		)

		return String(validatingUTF8: result)!
	}

	/**
		Converts hex-characters to a byte array.

		- parameters:
			- b64: The string.
			- ignore: A string containing characters that should be ignored.

			- returns: The byte array.
	*/
	func b64decode(_ b64: String, ignore: String? = nil) -> Bytes? {
		let variant: Int32 = libsodium.sodium_base64_VARIANT_ORIGINAL
		let encodedBytes = b64.utf8Bytes.map(Int8.init)
		let reservedCapacity = encodedBytes.count * 3 / 4 + 1
		var result = Bytes(count: reservedCapacity)
		let ignoreBytes = ignore?.utf8Bytes.map(Int8.init)
		var bytesWritten: size_t = 0

		let status = libsodium.sodium_base642bin(
			&result,
			reservedCapacity,
			encodedBytes,
			encodedBytes.count,
			ignoreBytes,
			&bytesWritten,
			nil,
			variant
		)
		guard status == sSuccess else {
			return nil
		}

		return result[..<bytesWritten].bytes
	}

	/**
		Converts a byte array to a Base64-encoded string.

		- parameters:
			- bin: The byte array.

		- returns: The Base64-encoded string.
	*/
	func b64encode(bytes: Bytes) -> String {
		let variant: Int32 = libsodium.sodium_base64_VARIANT_ORIGINAL
		let sizeOfResultInBytes = libsodium.sodium_base64_encoded_len(bytes.count, variant)
		var result = Bytes(count: sizeOfResultInBytes).map(Int8.init)

		libsodium.sodium_bin2base64(&result, sizeOfResultInBytes, bytes, bytes.count, variant)

		return String(validatingUTF8: result)!
	}

}
