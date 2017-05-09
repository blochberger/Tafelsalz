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
}
