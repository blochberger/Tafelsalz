import XCTest
@testable import Tafelsalz

class PasswordTest: XCTestCase {

    func testInitializer() {
		XCTAssertNotNil(Password("Unicorn", using: .ascii))
		XCTAssertNotNil(Password("Unicorn", using: .utf8))
		XCTAssertNotNil(Password("🦄", using: .utf8))
		XCTAssertNotNil(Password("Unicorn"))
		XCTAssertNotNil(Password("🦄"))
		XCTAssertNil(Password("🦄", using: .ascii))
    }

	func testHash() {
		let password1 = Password("Correct Horse Battery Staple")!
		let password2 = Password("Wrong Horse Battery Staple")!
		let optionalHashedPassword1 = password1.hash(complexity: .medium, memory: .medium)

		XCTAssertNotNil(optionalHashedPassword1)

		let hashedPassword1 = optionalHashedPassword1!

		XCTAssertTrue(password1.verifies(hashedPassword1))
		XCTAssertTrue(hashedPassword1.isVerified(by: password1))
		XCTAssertTrue(hashedPassword1.isVerified(by: Password("Correct Horse Battery Staple")!))

		XCTAssertFalse(hashedPassword1.isVerified(by: password2))
		XCTAssertFalse(password2.verifies(hashedPassword1))
	}

	func testEquality() {
		let password1 = Password("foo")!
		let password2 = Password("foo")!

		// Reflexivity
		XCTAssertEqual(password1, password1)

		// Symmetry
		XCTAssertEqual(password1, password2)
		XCTAssertEqual(password2, password1)

		// Test inequality
		XCTAssertNotEqual(password1, Password("FOO")!)
		XCTAssertNotEqual(password1, Password("bar")!)

		// Inequality due to different lengths
		let less = Password("foobar")!
		let more = Password("foo")!

		XCTAssertNotEqual(more, less)
		XCTAssertNotEqual(less, more)
	}

	func testKeyDerivation() {
		let password1 = Password("Correct Horse Battery Staple")!
		let password2 = Password("Wrong Horse Battery Staple")!
		let salt1 = Password.Salt()
		let salt2 = Password.Salt()

		KMAssertEqual(
			password1.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!,
			password1.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!
		)

		KMAssertEqual(
			password2.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!,
			password2.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!
		)

		KMAssertNotEqual(
			password1.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!,
			password2.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!
		)

		KMAssertNotEqual(
			password1.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt1)!,
			password1.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: .medium, memory: .medium, salt: salt2)!
		)
	}

	func testPublicParameters() {
		let password = Password("Correct Horse Battery Staple")!
		let derivedKey = password.derive(sizeInBytes: Password.DerivedKey.MinimumSizeInBytes)!

		let serialized = derivedKey.publicParameters
		let (salt, complexity, memory) = Password.DerivedKey.extractPublicParameters(bytes: serialized)!

		XCTAssertEqual(salt.bytes, derivedKey.salt.bytes)
		XCTAssertEqual(complexity, derivedKey.complexityLimit)
		XCTAssertEqual(memory, derivedKey.memoryLimit)
	}

}
