import XCTest
@testable import Tafelsalz

class SecretBoxTests: XCTestCase {

	// MARK: - SecretBox.SecretKey

    func testSecretKeyInitializer() {
		XCTAssertNotNil(SecretBox.SecretKey(), "Failed to initialize `libsodium`.")

		let secretKey = SecretBox.SecretKey()!

		XCTAssertEqual(
			secretKey.bytes.count,
			Int(SecretBox.SecretKey.SizeInBytes),
			"The secret key has an invalid size."
		)

		let otherSecretKey = SecretBox.SecretKey()!

		XCTAssertNotEqual(
			secretKey.bytes,
			otherSecretKey.bytes,
			"Two secret keys should not be equal."
		)
    }

	func testSecretKeyInitWithBytes() {
		let secretKey1 = SecretBox.SecretKey()!
		let optionalSecretKey2 = SecretBox.SecretKey(withBytes: secretKey1.bytes)

		XCTAssertNotNil(
			optionalSecretKey2,
			"Unexpectedly rejected valid byte sequence."
		)

		let secretKey2 = optionalSecretKey2!

		XCTAssertEqual(
			secretKey1.bytes,
			secretKey2.bytes,
			"Byte sequence was unexpectedly transformed."
		)

		let random = Random()!
		let randomBytes = random.bytes(count: SecretBox.SecretKey.SizeInBytes)
		let optionalSecretKey3 = SecretBox.SecretKey(withBytes: randomBytes)

		XCTAssertNotNil(
			optionalSecretKey2,
			"Unexpectedly rejected valid byte sequence."
		)

		let secretKey3 = optionalSecretKey3!

		XCTAssertEqual(
			secretKey3.bytes,
			randomBytes,
			"Byte sequence was unexpectedly transformed."
		)

		// Negative tests

		let lessBytes = random.bytes(count: SecretBox.SecretKey.SizeInBytes - 1)

		XCTAssertNil(
			SecretBox.SecretKey(withBytes: lessBytes),
			"Unexpectedly accepted byte sequence that is too short."
		)

		let moreBytes = random.bytes(count: SecretBox.SecretKey.SizeInBytes + 1)

		XCTAssertNil(
			SecretBox.SecretKey(withBytes: moreBytes),
			"Unexpectedly accepted byte sequence that is too long."
		)
	}

	// MARK: - SecretBox

	func testInitializer() {
		XCTAssertNotNil(
			SecretBox(),
			"Failed to initialize `libsodium` or to generate a secret key."
		)
	}

	func testEncryptionAndDecryption() {
		let random = Random()!
		let secretBox = SecretBox()!
		let originalPlaintext = "Hello, World!".data(using: .utf8)!
		let optionalCiphertext = secretBox.encrypt(data: originalPlaintext)

		XCTAssertNotNil(optionalCiphertext, "Failed to encrypt.")

		let ciphertext = optionalCiphertext!
		let otherCiphertext = secretBox.encrypt(data: originalPlaintext)!

		XCTAssertNotEqual(
			otherCiphertext.data,
			ciphertext.data,
			"Ciphertext of two encryption operations on the same plaintext is equal. Make sure the nonce was used only once!"
		)

		// Decryption of both ciphertexts should reveal the original plaintext

		let plaintext = secretBox.decrypt(data: ciphertext)
		let otherPlaintext = secretBox.decrypt(data: otherCiphertext)

		XCTAssertNotNil(plaintext, "Decryption failed.")
		XCTAssertNotNil(otherPlaintext, "Decryption failed.")

		XCTAssertEqual(plaintext, originalPlaintext, "Decrypted result is invalid.")
		XCTAssertEqual(otherPlaintext, originalPlaintext, "Decrypted result is invalid.")

		// Decryption should not be possible with invalid nonce

		let bytePosInNonce = Int(random.number(withUpperBound: SecretBox.SizeOfNonceInBytes))
		var dataWithInvalidNonce = ciphertext.data
		dataWithInvalidNonce[bytePosInNonce] = ~dataWithInvalidNonce[bytePosInNonce]

		XCTAssertNil(
			secretBox.decrypt(data: EncryptedData(dataWithInvalidNonce)),
			"Decryption should not be possible with invalid nonce."
		)

		// Decryption should not be possible with invalid MAC

		let bytePosInMac = Int(SecretBox.SizeOfNonceInBytes + random.number(withUpperBound: SecretBox.SizeOfMacInBytes))
		var dataWithInvalidMac = ciphertext.data
		dataWithInvalidMac[bytePosInMac] = ~dataWithInvalidMac[bytePosInMac]
		XCTAssertNil(
			secretBox.decrypt(data: EncryptedData(dataWithInvalidMac)),
			"Decryption should not be possible with invalid MAC"
		)

		// Decryption should not be possible with invalid ciphertext

		let prefixSize = SecretBox.SizeOfNonceInBytes + SecretBox.SizeOfMacInBytes
		let bytePosInCiphertext = Int(prefixSize + random.number(withUpperBound: PInt(ciphertext.data.count) - prefixSize))
		var dataWithInvalidCiphertext = ciphertext.data
		dataWithInvalidCiphertext[bytePosInCiphertext] = ~dataWithInvalidCiphertext[bytePosInCiphertext]
		XCTAssertNil(
			secretBox.decrypt(data: EncryptedData(dataWithInvalidCiphertext)),
			"Decryption should not be possible with invalid ciphertext"
		)

		// Decryption should not be possible with invalid key

		let otherSecretBox = SecretBox()!
		XCTAssertNil(
			otherSecretBox.decrypt(data: ciphertext),
			"Decryption should not be possible with invalid key."
		)

		// Try to decrypt byte sequence that is too short

		XCTAssertNil(
			secretBox.decrypt(data: EncryptedData(random.bytes(count: prefixSize))),
			"Decryption should fail if there is no ciphertext."
		)
	}
}
