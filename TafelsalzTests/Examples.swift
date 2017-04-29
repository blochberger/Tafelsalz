import XCTest
@testable import Tafelsalz

class Examples: XCTestCase {

	func testSymmetricEncryption() {
		let secretBox = SecretBox()!
		let plaintext = "Hello, World!".data(using: .utf8)!
		let ciphertext = secretBox.encrypt(data: plaintext)!
		let decrypted = secretBox.decrypt(data: ciphertext)!

		XCTAssertEqual(decrypted, plaintext)
	}

	func testPasswordHashing() {
		let password = Password("Correct Horse Battery Staple")!
		let hashedPassword = password.hash()!

		// Store `hashedPassword.string` to database.

		// If a user wants to authenticate, just read it from the database and
		// verify it against the password given by the user.
		if hashedPassword.isVerified(by: password) {
			// The user is authenticated successfully.
		}
	}

}
