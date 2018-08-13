import XCTest
@testable import Tafelsalz

class SecretBoxTests: XCTestCase {

	// MARK: - SecretBox.SecretKey

    func testSecretKey() {
		typealias SecretKey = SecretBox.SecretKey

		let defaultInitializer = { SecretKey() }
		let capturingInitializer: (inout Bytes) -> SecretKey? = { SecretKey(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: SecretKey.SizeInBytes, eq: { $0.copyBytes() }, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: SecretKey.SizeInBytes, eq: { $0.copyBytes() }, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: SecretKey.SizeInBytes, withCapturingInitializer: capturingInitializer)
    }

	// MARK: - SecretBox.Nonce

	func testNonce() {
		typealias Nonce = SecretBox.Nonce

		let defaultInitializer = { Nonce() }
		let capturingInitializer: (inout Bytes) -> Nonce? = { Nonce(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: Nonce.SizeInBytes, eq: { $0 }, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: Nonce.SizeInBytes, eq: { $0 }, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: Nonce.SizeInBytes, withCapturingInitializer: capturingInitializer)

		let nonce = Nonce()
		XCTAssertEqual(nonce, nonce)
		XCTAssertNotEqual(Nonce(), nonce)
	}

	// MARK: - AuthenticationCode

	func testAuthenticationCode() {
		typealias AuthenticationCode = SecretBox.AuthenticationCode

		let capturingInitializer: (inout Bytes) -> AuthenticationCode? = { AuthenticationCode(bytes: &$0) }

		KeyMaterialTest.metaTestCapturingInitializer(of: AuthenticationCode.SizeInBytes, eq: { $0 }, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: AuthenticationCode.SizeInBytes, withCapturingInitializer: capturingInitializer)
	}

	// MARK: - AuthenticatedCiphertext

	func testAuthenticatedCiphertext() {
		typealias Nonce = SecretBox.Nonce
		typealias AuthenticationCode = SecretBox.AuthenticationCode
		typealias AuthenticatedCiphertext = SecretBox.AuthenticatedCiphertext

		let ciphertextSizeInBytes: UInt32 = 32
		let sizeInBytes = AuthenticatedCiphertext.PrefixSizeInBytes + ciphertextSizeInBytes

		let nonce = Nonce()
		var authenticationCodeBytes = Random.bytes(count: AuthenticationCode.SizeInBytes)
		let authenticationCode = AuthenticationCode(bytes: &authenticationCodeBytes)!
		let ciphertext = Ciphertext(Random.bytes(count: ciphertextSizeInBytes))
		let bytes = nonce.copyBytes() + authenticationCode.copyBytes() + ciphertext.bytes

		let authenticatedCiphertext1 = AuthenticatedCiphertext(nonce: nonce, authenticationCode: authenticationCode, ciphertext: ciphertext)

		XCTAssertEqual(authenticatedCiphertext1.sizeInBytes, sizeInBytes)
		XCTAssertEqual(authenticatedCiphertext1.nonce, nonce)
		XCTAssertEqual(authenticatedCiphertext1.authenticationCode, authenticationCode)
		XCTAssertEqual(authenticatedCiphertext1.ciphertext.bytes, ciphertext.bytes)
		XCTAssertEqual(authenticatedCiphertext1.bytes, bytes)

		let authenticatedCiphertext2 = AuthenticatedCiphertext(bytes: bytes)!

		XCTAssertEqual(authenticatedCiphertext2.sizeInBytes, sizeInBytes)
		XCTAssertEqual(authenticatedCiphertext2.nonce, nonce)
		XCTAssertEqual(authenticatedCiphertext2.authenticationCode, authenticationCode)
		XCTAssertEqual(authenticatedCiphertext2.ciphertext.bytes, ciphertext.bytes)
		XCTAssertEqual(authenticatedCiphertext2.bytes, bytes)

		let tooShort = Random.bytes(count: AuthenticatedCiphertext.PrefixSizeInBytes)

		XCTAssertNil(AuthenticatedCiphertext(bytes: tooShort))
	}

	// MARK: - SecretBox

	func testEncryptionAndDecryption() {
		let secretBox = SecretBox()
		let originalPlaintext = "Hello, World!".utf8Bytes
		let ciphertext = secretBox.encrypt(plaintext: originalPlaintext)

		XCTAssertNotEqual(originalPlaintext, ciphertext.bytes)

		let otherCiphertext = secretBox.encrypt(plaintext: originalPlaintext)

		// Test for nonce reuse
		XCTAssertNotEqual(otherCiphertext.nonce, ciphertext.nonce)
		XCTAssertEqual(secretBox.encrypt(plaintext: originalPlaintext, with: ciphertext.nonce).bytes, ciphertext.bytes)

		// Test that a different nonce results in a different authentication code
		XCTAssertNotEqual(otherCiphertext.authenticationCode, ciphertext.authenticationCode)

		// Test that a different nonce results in a different ciphertext
		XCTAssertNotEqual(otherCiphertext.ciphertext.bytes, ciphertext.ciphertext.bytes)

		// Decryption of both ciphertexts should reveal the original plaintext

		let plaintext = secretBox.decrypt(ciphertext: ciphertext)
		let otherPlaintext = secretBox.decrypt(ciphertext: otherCiphertext)

		// Test if decryption did succeed
		XCTAssertNotNil(plaintext)
		XCTAssertNotNil(otherPlaintext)

		// Test if the decrypted text is equal to the original text
		XCTAssertEqual(plaintext, originalPlaintext)
		XCTAssertEqual(otherPlaintext, originalPlaintext)

		// Test encryption with padding
		let paddedCiphertext = secretBox.encrypt(plaintext: originalPlaintext, padding: .padded(blockSize: 16))

		XCTAssertGreaterThan(paddedCiphertext.sizeInBytes, ciphertext.sizeInBytes)

		let unpaddedPlaintext = secretBox.decrypt(ciphertext: paddedCiphertext, padding: .padded(blockSize: 16))!

		XCTAssertEqual(unpaddedPlaintext, originalPlaintext)

		// Decryption will not fail, if no padding is specified, but the
		// plaintext is different.
		let paddedPlaintext = secretBox.decrypt(ciphertext: paddedCiphertext)
		XCTAssertNotEqual(paddedPlaintext, originalPlaintext)

		// Decryption should fail, if padding is invalid
		XCTAssertNil(secretBox.decrypt(ciphertext: paddedCiphertext, padding: .padded(blockSize: 3)))

		// Decryption should not be possible with invalid nonce

		let bytePosInNonce = Int(Random.number(withUpperBound: SecretBox.Nonce.SizeInBytes))
		var dataWithInvalidNonce = ciphertext.bytes
		dataWithInvalidNonce[bytePosInNonce] = ~dataWithInvalidNonce[bytePosInNonce]
		let ciphertextWithInvalidNonce = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidNonce)!

		XCTAssertNil(secretBox.decrypt(ciphertext: ciphertextWithInvalidNonce))

		// Decryption should not be possible with invalid MAC

		let bytePosInMac = Int(SecretBox.Nonce.SizeInBytes + Random.number(withUpperBound: SecretBox.AuthenticationCode.SizeInBytes))
		var dataWithInvalidMac = ciphertext.bytes
		dataWithInvalidMac[bytePosInMac] = ~dataWithInvalidMac[bytePosInMac]
		let ciphertextWithInvalidMac = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidMac)!

		XCTAssertNil(secretBox.decrypt(ciphertext: ciphertextWithInvalidMac))

		// Decryption should not be possible with invalid ciphertext

		let prefixSize = SecretBox.Nonce.SizeInBytes + SecretBox.AuthenticationCode.SizeInBytes
		let bytePosInCiphertext = Int(prefixSize + Random.number(withUpperBound: UInt32(ciphertext.bytes.count) - prefixSize))
		var dataWithInvalidCiphertext = ciphertext.bytes
		dataWithInvalidCiphertext[bytePosInCiphertext] = ~dataWithInvalidCiphertext[bytePosInCiphertext]
		let ciphertextWithInvalidBytes = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidCiphertext)!

		XCTAssertNil(secretBox.decrypt(ciphertext: ciphertextWithInvalidBytes))

		// Decryption should not be possible with invalid key

		let otherSecretBox = SecretBox()
		XCTAssertNil(otherSecretBox.decrypt(ciphertext: ciphertext))
	}

}
