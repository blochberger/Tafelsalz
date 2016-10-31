//
//  Examples.swift
//  Tafelsalz
//
//  Created by Maximilian Blochberger on 2016-10-31.
//  Copyright © 2016 Universität Hamburg. All rights reserved.
//

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
