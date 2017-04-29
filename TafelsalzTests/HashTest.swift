import XCTest
@testable import Tafelsalz

import libsodium

class HashTest: XCTestCase {

	// MARK: - Sanitize mapped enumeration values

    func testMemoryLimitInBytesValues() {
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Interactive.rawValue,
			PInt(libsodium.crypto_pwhash_memlimit_interactive())
		)
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Moderate.rawValue,
			PInt(libsodium.crypto_pwhash_memlimit_moderate())
		)
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Sensitive.rawValue,
			PInt(libsodium.crypto_pwhash_memlimit_sensitive())
		)
    }

	func testComplexityLimitValues() {
		XCTAssertEqual(
			Hash.ComplexityLimit.Interactive.rawValue,
			PInt(libsodium.crypto_pwhash_opslimit_interactive())
		)
		XCTAssertEqual(
			Hash.ComplexityLimit.Moderate.rawValue,
			PInt(libsodium.crypto_pwhash_opslimit_moderate())
		)
		XCTAssertEqual(
			Hash.ComplexityLimit.Sensitive.rawValue,
			PInt(libsodium.crypto_pwhash_opslimit_sensitive())
		)
	}

	func testPasswordHashingAlgorithmValues() {
		XCTAssertEqual(
			Hash.PasswordHashingAlgorithm.Argon2i_v13.rawValue,
			PInt(libsodium.crypto_pwhash_alg_argon2i13())
		)
		XCTAssertEqual(
			Hash.DefaultPasswordHashingAlgorithm.rawValue,
			PInt(libsodium.crypto_pwhash_alg_default())
		)
	}

	// MARK: - Hash.Salt

	func testSaltInitializer() {
		XCTAssertNotNil(Hash.Salt(), "Failed to initilize `libsodium`.")

		let salt = Hash.Salt()!

		XCTAssertEqual(
			salt.bytes.count,
			Int(Hash.Salt.SizeInBytes),
			"The salt has an invalid size."
		)

		let otherSalt = Hash.Salt()!

		XCTAssertNotEqual(
			salt.bytes,
			otherSalt.bytes,
			"Two salts should not be equal."
		)
	}

	// MARK: - Hash

	func testHashInitializer() {
		let value = "foobar".data(using: .utf8)!
		let length: PInt = 16
		XCTAssertNotNil(Hash(withConfidentialValue: value, andOutputLengthInBytes: length))

		let hash = Hash(withConfidentialValue: value, andOutputLengthInBytes: length)!

		XCTAssertEqual(
			PInt(hash.bytes.count),
			length,
			"Hash has invalid size."
		)

		let otherHash = Hash(withConfidentialValue: value, andOutputLengthInBytes: length)!

		XCTAssertNotEqual(
			hash.salt.bytes,
			otherHash.salt.bytes,
			"Two hashes should use different salts by default"
		)

		XCTAssertNotEqual(
			hash.bytes,
			otherHash.bytes,
			"Two hashes with different salts should be different."
		)

		let equalHash = Hash(withConfidentialValue: value, andOutputLengthInBytes: length, andSalt: hash.salt)!

		XCTAssertEqual(
			hash.salt.bytes,
			equalHash.salt.bytes,
			"The salt value passed to the initialized was not stored by the instance."
		)

		XCTAssertEqual(
			hash.bytes,
			equalHash.bytes,
			"Two hashes produced with the same salt should be equal."
		)
	}

}
