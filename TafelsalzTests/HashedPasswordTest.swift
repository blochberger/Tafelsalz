import XCTest
@testable import Tafelsalz

class HashedPasswordTest: XCTestCase {

    func testInitializer() {
		let validAsciiCharacter = UInt8(Random.number(withUpperBound: 0x7F))
		let sizeInBytes = Int(HashedPassword.SizeInBytes)

		XCTAssertNotNil(HashedPassword(Data(repeating: validAsciiCharacter, count: sizeInBytes)))
        XCTAssertNil(HashedPassword(Data(repeating: validAsciiCharacter, count: sizeInBytes - 1)))
		XCTAssertNil(HashedPassword(Data(repeating: validAsciiCharacter, count: sizeInBytes + 1)))

		XCTAssertNil(HashedPassword(Data(repeating: 0xFF, count: sizeInBytes)))
    }

	func testString() {
		let validAsciiCharacter = UInt8(Random.number(withUpperBound: 0x7F))
		let bytes = Data(repeating: validAsciiCharacter, count: Int(HashedPassword.SizeInBytes))
		let hashedPassword = HashedPassword(bytes)!

		XCTAssertEqual(String(data: bytes, encoding: .nonLossyASCII)!, hashedPassword.string)
	}
}
