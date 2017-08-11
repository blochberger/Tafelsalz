import XCTest
@testable import Tafelsalz

class Examples: XCTestCase {

	func testSymmetricEncryptionWithEphemeralKeys() {
		let secretBox = SecretBox()!
		let plaintext = "Hello, World!".data(using: .utf8)!
		let ciphertext = secretBox.encrypt(data: plaintext)!
		let decrypted = secretBox.decrypt(data: ciphertext)!

		XCTAssertEqual(decrypted, plaintext)
	}

	func testSymmetricEncryptionWithPersistedKeys() {
		// Create a persona
		let alice = Persona(uniqueName: "Alice")

		// Once a secret of that persona is used, it will be persisted in the
		// system's Keychain.
		let secretBox = SecretBox(persona: alice)!

		// Use your SecretBox as usual
		let plaintext = "Hello, World!".data(using: .utf8)!
		let ciphertext = secretBox.encrypt(data: plaintext)!
		let decrypted = secretBox.decrypt(data: ciphertext)!

		// Forget the persona and remove all related Keychain entries
		try! Persona.forget(alice)

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

	func testPublicGenericHashing() {
		let data = "Hello, World!".data(using: .utf8)!
		let hash = GenericHash(bytes: data)

		XCTAssertNotNil(hash)
	}

	func testPrivateGenericHashingWithPersistedKeys() {
		// Create a persona
		let alice = Persona(uniqueName: "Alice")

		// Generate a personalized hash for that persona
		let data = "Hello, World!".data(using: .utf8)!
		let hash = GenericHash(bytes: data, for: alice)

		// Forget the persona and remove all related Keychain entries
		try! Persona.forget(alice)

		XCTAssertNotNil(hash)
	}
}
