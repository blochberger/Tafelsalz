import XCTest
@testable import Tafelsalz

class HashTest: XCTestCase {

	// MARK: - Sanitize mapped values

    func testMemoryLimitInBytesValues() {
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Interactive.rawValue,
			Hash.ExpectedMemoryLimitInBytes_Interactive
		)
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Moderate.rawValue,
			Hash.ExpectedMemoryLimitInBytes_Moderate
		)
		XCTAssertEqual(
			Hash.MemoryLimitInBytes.Sensitive.rawValue,
			Hash.ExpectedMemoryLimitInBytes_Sensitive
		)

		XCTAssertTrue(Hash.memoryLimitsAreSane())
    }

	func testComplexityLimitValues() {
		XCTAssertEqual(
			Hash.ComplexityLimit.Interactive.rawValue,
			Hash.ExpectedComplexityLimit_Interactive
		)
		XCTAssertEqual(
			Hash.ComplexityLimit.Moderate.rawValue,
			Hash.ExpectedComplexityLimit_Moderate
		)
		XCTAssertEqual(
			Hash.ComplexityLimit.Sensitive.rawValue,
			Hash.ExpectedComplexityLimit_Sensitive
		)

		XCTAssertTrue(Hash.complexityLimitsAreSane())
	}

	func testPasswordHashingAlgorithmValues() {
		XCTAssertEqual(
			Hash.PasswordHashingAlgorithm.Argon2i_v13.rawValue,
			Hash.ExpectedPasswordHashingAlgorithm_Argon2i_v13
		)
		XCTAssertEqual(
			Hash.DefaultPasswordHashingAlgorithm.rawValue,
			Hash.ExpectedPasswordHashingAlgorithm_Default
		)
		XCTAssertEqual(
			Hash.DefaultPasswordHashingAlgorithm,
			Hash.PasswordHashingAlgorithm.Argon2i_v13
		)
		XCTAssertTrue(Hash.passwordHashingAlgorithmValuesAreSane())
	}

	func testMappedValues() {
		XCTAssertTrue(Hash.limitsAreSane())
		XCTAssertTrue(Hash.mappedValuesAreSane())
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
