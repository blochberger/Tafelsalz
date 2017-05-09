import XCTest
@testable import Tafelsalz

class KeyMaterialTest: XCTestCase {

	func testDefaultInitializer() {
		let sizeInBytes: PInt = 32

		XCTAssertNotNil(
			KeyMaterial(sizeInBytes: sizeInBytes),
			"Failed to initialize `libsodium`."
		)

		let keyMaterial = KeyMaterial(sizeInBytes: sizeInBytes)!

		XCTAssertEqual(
			keyMaterial.sizeInBytes,
			sizeInBytes,
			"The size does not match!"
		)

		let otherKeyMaterial = KeyMaterial(sizeInBytes: sizeInBytes)!

		XCTAssertEqual(keyMaterial, keyMaterial) // Reflexivity

		XCTAssertNotEqual(
			keyMaterial,
			otherKeyMaterial,
			"Generated key material should not be equal!"
		)

		XCTAssertNotEqual(
			keyMaterial,
			KeyMaterial(sizeInBytes: sizeInBytes - 1),
			"Generated key material of different size should not be equal"
		)
	}

    func testCapturingInitializer() {
		let sizeInBytes: PInt = 32
		let random = Random()!
		let data = random.bytes(count: sizeInBytes)

		var tmp = Data(data)
		let optionalKeyMaterial = KeyMaterial(bytes: &tmp)

		XCTAssertNotNil(optionalKeyMaterial)

		let keyMaterial = optionalKeyMaterial!

		XCTAssertEqual(keyMaterial.copyBytes(), data)
    }

	func testEquality() {
		let sizeInBytes: PInt = 32

		let keyMaterial1 = KeyMaterial(sizeInBytes: sizeInBytes)!
		var bytes = keyMaterial1.withUnsafeBytes { Data(bytes: $0, count: Int(sizeInBytes)) }
		let keyMaterial2 = KeyMaterial(bytes: &bytes)!
		let otherKeyMaterial = KeyMaterial(sizeInBytes: sizeInBytes)!

		// Reflexivity
		XCTAssertEqual(keyMaterial1, keyMaterial1)
		XCTAssertEqual(keyMaterial1, keyMaterial2)
		XCTAssertEqual(keyMaterial2, keyMaterial1)

		XCTAssertNotEqual(keyMaterial1, otherKeyMaterial)

		var long = Random()!.bytes(count: sizeInBytes + 1)
		var short = long.subdata(in: 0..<Int(sizeInBytes))

		XCTAssertNotEqual(
			KeyMaterial(bytes: &long)!,
			KeyMaterial(bytes: &short)!,
			"Keys with different lengths should not be equal!"
		)
	}

}
