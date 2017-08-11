import XCTest
@testable import Tafelsalz

class KeyMaterialTest: XCTestCase {

	// MARK: - Meta tests

	static func metaTestDefaultInitializer<T: KeyMaterial>(
		of fixedSizeInBytes: PInt,
		with initializer: () -> T?
	) {
		let instance1 = initializer()!

		// Test expected size limitation
		XCTAssertEqual(instance1.sizeInBytes, fixedSizeInBytes)

		// Test reflexivity
		XCTAssertEqual(instance1.copyBytes(), instance1.copyBytes())

		// Test uniqueness after initialization
		XCTAssertNotEqual(instance1.copyBytes(), initializer()!.copyBytes())
	}

	static func metaTestCapturingInitializer<T: KeyMaterial>(
		minimumSizeInBytes: PInt,
		maximumSizeInBytes: PInt,
		with initializer: (inout Data) -> T?
	) {
		let random = Random()!

		let sizesInBytes = (minimumSizeInBytes == maximumSizeInBytes) ? [minimumSizeInBytes] : [minimumSizeInBytes, maximumSizeInBytes]
		for sizeInBytes in sizesInBytes {
			let expectedBytes = random.bytes(count: sizeInBytes)
			var bytes = Data(expectedBytes)
			let optionalInstance = initializer(&bytes)

			// Test creating instance from byte sequence with correct size
			XCTAssertNotNil(optionalInstance)

			let instance = optionalInstance!

			// Test expected size limitation
			XCTAssertEqual(instance.sizeInBytes, sizeInBytes)

			// Test equality of byte sequences
			XCTAssertEqual(instance.copyBytes(), expectedBytes)

			// Test that passed argument is zeroed
			XCTAssertEqual(bytes, Data(count: Int(sizeInBytes)))

			XCTAssertEqual(instance.copyBytes(), instance.copyBytes())
		}

		// Test creating instance from byte sequence with incorrect size
		var tooShort = random.bytes(count: minimumSizeInBytes - 1)
		var tooLong = random.bytes(count: maximumSizeInBytes + 1)

		XCTAssertNil(initializer(&tooShort))
		XCTAssertNil(initializer(&tooLong))

		// Test if arguments passed have been wiped unexpectedly
		XCTAssertNotEqual(tooShort, Data(count: tooShort.count))
		XCTAssertNotEqual(tooLong, Data(count: tooLong.count))
	}

	static func metaTestCapturingInitializer<T: KeyMaterial>(
		of fixedSizeInBytes: PInt,
		with initializer: (inout Data) -> T?
		) {
		metaTestCapturingInitializer(minimumSizeInBytes: fixedSizeInBytes, maximumSizeInBytes: fixedSizeInBytes, with: initializer)
	}

	static func metaTestEquality<T: KeyMaterial>(
		of fixedSizeInBytes: PInt,
		withCapturingInitializer initializer: (inout Data) -> T?
	) {
		let random = Random()!
		let bytes = random.bytes(count: fixedSizeInBytes)
		let otherBytes = random.bytes(count: fixedSizeInBytes)
		var tmpBytes1 = Data(bytes)
		var tmpBytes2 = Data(bytes)
		var tmpBytes3 = Data(otherBytes)
		let keyMaterial1 = initializer(&tmpBytes1)!
		let keyMaterial2 = initializer(&tmpBytes2)!
		let keyMaterial3 = initializer(&tmpBytes3)!

		// Reflexivity
		XCTAssertTrue(keyMaterial1.isEqual(to: keyMaterial1))
		XCTAssertTrue(keyMaterial1.isFingerprintEqual(to: keyMaterial1))

		// Symmetry
		XCTAssertTrue(keyMaterial1.isEqual(to: keyMaterial2))
		XCTAssertTrue(keyMaterial2.isEqual(to: keyMaterial1))
		XCTAssertTrue(keyMaterial1.isFingerprintEqual(to: keyMaterial2))
		XCTAssertTrue(keyMaterial2.isFingerprintEqual(to: keyMaterial1))

		// Inequality due to different byte sequences
		XCTAssertFalse(keyMaterial1.isEqual(to: keyMaterial3))
		XCTAssertFalse(keyMaterial3.isEqual(to: keyMaterial1))
		XCTAssertFalse(keyMaterial1.isFingerprintEqual(to: keyMaterial3))
		XCTAssertFalse(keyMaterial3.isFingerprintEqual(to: keyMaterial1))
	}

	// MARK: - Tests

	func testDefaultInitializer() {
		let sizeInBytes: PInt = 32

		KeyMaterialTest.metaTestDefaultInitializer(of: sizeInBytes) { KeyMaterial(sizeInBytes: sizeInBytes) }
	}

    func testCapturingInitializer() {
		let sizeInBytes: PInt = 32

		KeyMaterialTest.metaTestCapturingInitializer(of: sizeInBytes) {
			PInt($0.count) == sizeInBytes ? KeyMaterial(bytes: &$0) : nil
		}
    }

	func testEquality() {
		let sizeInBytes: PInt = 32

		KeyMaterialTest.metaTestEquality(of: sizeInBytes) { KeyMaterial(bytes: &$0) }

		// Inequality due to different lengths
		var moreBytes = Random()!.bytes(count: sizeInBytes + 1)
		var lessBytes = moreBytes.subdata(in: 0..<Int(sizeInBytes))
		let more = KeyMaterial(bytes: &lessBytes)!
		let less = KeyMaterial(bytes: &moreBytes)!

		// Inequality can only be tested via fingerprints, see documentation.
		XCTAssertFalse(more.isFingerprintEqual(to: less))
		XCTAssertFalse(less.isFingerprintEqual(to: more))
	}

}
