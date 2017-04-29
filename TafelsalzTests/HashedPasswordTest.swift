import XCTest
@testable import Tafelsalz

class HashedPasswordTest: XCTestCase {

    func testInitializer() {
		XCTAssertNotNil(
			HashedPassword(Random()!.bytes(count: HashedPassword.SizeInBytes))
		)

        XCTAssertNil(
			HashedPassword(Random()!.bytes(count: HashedPassword.SizeInBytes - 1)),
			"Unexpectedly created HashedPassword with input that is too small!"
		)

		XCTAssertNil(
			HashedPassword(Random()!.bytes(count: HashedPassword.SizeInBytes + 1)),
			"Unexpectedly created HashedPassword with input that is too big!"
		)
    }

	func testString() {
		let bytes = Random()!.bytes(count: HashedPassword.SizeInBytes)
		let hashedPassword = HashedPassword(bytes)

		XCTAssertEqual(String(data: bytes, encoding: .ascii)!, hashedPassword?.string)
	}
}
