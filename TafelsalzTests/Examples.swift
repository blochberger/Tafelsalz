import XCTest
@testable import Tafelsalz

class Examples: XCTestCase {

	func testSymmetricEncryption() {
		let secretBox = SecretBox()!
		let plaintext = "Hello, World!".data(using: .utf8)!
		let ciphertext = secretBox.encrypt(data: plaintext)!
		let decrypted = secretBox.decrypt(data: ciphertext)!

		XCTAssertEqual(decrypted, plaintext)
	}

}
