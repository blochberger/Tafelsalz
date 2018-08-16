import XCTest
@testable import Tafelsalz

class HashedPasswordTest: XCTestCase {

	func testInitializer() {
		let validAsciiCharacter = UInt8(Random.number(withUpperBound: 0x7F))
		let sizeInBytes = Int(HashedPassword.SizeInBytes)

		XCTAssertNotNil(HashedPassword(Bytes(repeating: validAsciiCharacter, count: sizeInBytes)))
		XCTAssertNil(HashedPassword(Bytes(repeating: validAsciiCharacter, count: sizeInBytes - 1)))
		XCTAssertNil(HashedPassword(Bytes(repeating: validAsciiCharacter, count: sizeInBytes + 1)))

		XCTAssertNil(HashedPassword(Bytes(repeating: 0xFF, count: sizeInBytes)))
	}

	func testString() {
		let validAsciiCharacter = UInt8(Random.number(withUpperBound: 0x7F))
		let bytes = Bytes(repeating: validAsciiCharacter, count: Int(HashedPassword.SizeInBytes))
		let hashedPassword = HashedPassword(bytes)!

		XCTAssertEqual(String(bytes: bytes, encoding: .nonLossyASCII)!, hashedPassword.string)
	}
}
