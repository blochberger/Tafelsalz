import XCTest
@testable import Tafelsalz

class SecretBoxTests: XCTestCase {

	// MARK: - SecretBox.SecretKey

    func testSecretKey() {
		typealias SecretKey = SecretBox.SecretKey

		let defaultInitializer = { SecretKey() }
		let capturingInitializer: (inout Data) -> SecretKey? = { SecretKey(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: SecretKey.SizeInBytes, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: SecretKey.SizeInBytes, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: SecretKey.SizeInBytes, withCapturingInitializer: capturingInitializer)
    }

	// MARK: - SecretBox.Nonce

	func testNonce() {
		typealias Nonce = SecretBox.Nonce

		let defaultInitializer = { Nonce() }
		let capturingInitializer: (inout Data) -> Nonce? = { Nonce(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: Nonce.SizeInBytes, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: Nonce.SizeInBytes, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: Nonce.SizeInBytes, withCapturingInitializer: capturingInitializer)
	}

	// MARK: - AuthenticationCode

	func testAuthenticationCode() {
		typealias AuthenticationCode = SecretBox.AuthenticationCode

		let capturingInitializer: (inout Data) -> AuthenticationCode? = { AuthenticationCode(bytes: &$0) }

		KeyMaterialTest.metaTestCapturingInitializer(of: AuthenticationCode.SizeInBytes, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: AuthenticationCode.SizeInBytes, withCapturingInitializer: capturingInitializer)
	}

	// MARK: - AuthenticatedCiphertext

	func testAuthenticatedCiphertext() {
		typealias Nonce = SecretBox.Nonce
		typealias AuthenticationCode = SecretBox.AuthenticationCode
		typealias AuthenticatedCiphertext = SecretBox.AuthenticatedCiphertext

		let random = Random()!
		let ciphertextSizeInBytes: PInt = 32
		let sizeInBytes = AuthenticatedCiphertext.PrefixSizeInBytes + ciphertextSizeInBytes

		let nonce = Nonce()!
		var authenticationCodeBytes = random.bytes(count: AuthenticationCode.SizeInBytes)
		let authenticationCode = AuthenticationCode(bytes: &authenticationCodeBytes)!
		let ciphertext = Ciphertext(random.bytes(count: ciphertextSizeInBytes))
		let bytes = nonce.copyBytes() + authenticationCode.copyBytes() + ciphertext.bytes

		let authenticatedCiphertext1 = AuthenticatedCiphertext(nonce: nonce, authenticationCode: authenticationCode, ciphertext: ciphertext)

		XCTAssertEqual(authenticatedCiphertext1.sizeInBytes, sizeInBytes)
		XCTAssertEqual(authenticatedCiphertext1.nonce, nonce)
		XCTAssertEqual(authenticatedCiphertext1.authenticationCode, authenticationCode)
		XCTAssertEqual(authenticatedCiphertext1.ciphertext.bytes, ciphertext.bytes)
		XCTAssertEqual(authenticatedCiphertext1.bytes, bytes)

		let optionalAuthenticatedCiphertext2 = AuthenticatedCiphertext(bytes: bytes)

		XCTAssertNotNil(optionalAuthenticatedCiphertext2)

		let authenticatedCiphertext2 = optionalAuthenticatedCiphertext2!

		XCTAssertEqual(authenticatedCiphertext2.sizeInBytes, sizeInBytes)
		XCTAssertEqual(authenticatedCiphertext2.nonce, nonce)
		XCTAssertEqual(authenticatedCiphertext2.authenticationCode, authenticationCode)
		XCTAssertEqual(authenticatedCiphertext2.ciphertext.bytes, ciphertext.bytes)
		XCTAssertEqual(authenticatedCiphertext2.bytes, bytes)

		let tooShort = random.bytes(count: AuthenticatedCiphertext.PrefixSizeInBytes)

		XCTAssertNil(AuthenticatedCiphertext(bytes: tooShort))
	}

	// MARK: - SecretBox

	func testInitializer() {
		XCTAssertNotNil(SecretBox())
	}

	func testEncryptionAndDecryption() {
		let random = Random()!
		let secretBox = SecretBox()!
		let originalPlaintext = "Hello, World!".data(using: .utf8)!
		let optionalCiphertext = secretBox.encrypt(data: originalPlaintext)

		// Test if decryption did succeed
		XCTAssertNotNil(optionalCiphertext)

		let ciphertext = optionalCiphertext!

		XCTAssertNotEqual(originalPlaintext, ciphertext.bytes)

		let otherCiphertext = secretBox.encrypt(data: originalPlaintext)!

		// Test for nonce reuse
		XCTAssertNotEqual(otherCiphertext.nonce, ciphertext.nonce)
		XCTAssertEqual(secretBox.encrypt(data: originalPlaintext, with: ciphertext.nonce)?.bytes, ciphertext.bytes)

		// Test that a different nonce results in a different authentication code
		XCTAssertNotEqual(otherCiphertext.authenticationCode, ciphertext.authenticationCode)

		// Test that a different nonce results in a different ciphertext
		XCTAssertNotEqual(otherCiphertext.ciphertext.bytes, ciphertext.ciphertext.bytes)

		// Decryption of both ciphertexts should reveal the original plaintext

		let plaintext = secretBox.decrypt(data: ciphertext)
		let otherPlaintext = secretBox.decrypt(data: otherCiphertext)

		// Test if decryption did succeed
		XCTAssertNotNil(plaintext)
		XCTAssertNotNil(otherPlaintext)

		// Test if the decrypted text is equal to the original text
		XCTAssertEqual(plaintext, originalPlaintext)
		XCTAssertEqual(otherPlaintext, originalPlaintext)

		// Decryption should not be possible with invalid nonce

		let bytePosInNonce = Int(random.number(withUpperBound: SecretBox.Nonce.SizeInBytes))
		var dataWithInvalidNonce = ciphertext.bytes
		dataWithInvalidNonce[bytePosInNonce] = ~dataWithInvalidNonce[bytePosInNonce]
		let ciphertextWithInvalidNonce = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidNonce)!

		XCTAssertNil(secretBox.decrypt(data: ciphertextWithInvalidNonce))

		// Decryption should not be possible with invalid MAC

		let bytePosInMac = Int(SecretBox.Nonce.SizeInBytes + random.number(withUpperBound: SecretBox.AuthenticationCode.SizeInBytes))
		var dataWithInvalidMac = ciphertext.bytes
		dataWithInvalidMac[bytePosInMac] = ~dataWithInvalidMac[bytePosInMac]
		let ciphertextWithInvalidMac = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidMac)!

		XCTAssertNil(secretBox.decrypt(data: ciphertextWithInvalidMac))

		// Decryption should not be possible with invalid ciphertext

		let prefixSize = SecretBox.Nonce.SizeInBytes + SecretBox.AuthenticationCode.SizeInBytes
		let bytePosInCiphertext = Int(prefixSize + random.number(withUpperBound: PInt(ciphertext.bytes.count) - prefixSize))
		var dataWithInvalidCiphertext = ciphertext.bytes
		dataWithInvalidCiphertext[bytePosInCiphertext] = ~dataWithInvalidCiphertext[bytePosInCiphertext]
		let ciphertextWithInvalidBytes = SecretBox.AuthenticatedCiphertext(bytes: dataWithInvalidCiphertext)!

		XCTAssertNil(secretBox.decrypt(data: ciphertextWithInvalidBytes))

		// Decryption should not be possible with invalid key

		let otherSecretBox = SecretBox()!
		XCTAssertNil(otherSecretBox.decrypt(data: ciphertext))
	}
}
