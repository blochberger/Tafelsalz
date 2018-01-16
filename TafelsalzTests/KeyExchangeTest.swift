import XCTest

import Tafelsalz

class KeyExchangeTest: XCTestCase {

	func testKeyPairExchange() {
		let alice = KeyExchange(side: .client)
		let bob = KeyExchange(side: .server)

		let alicesSessionKeys = alice.sessionKeys(for: bob.publicKey)!
		let bobsSessionKeys = bob.sessionKeys(for: alice.publicKey)!

		KMAssertEqual(alicesSessionKeys.rx, bobsSessionKeys.tx)
		KMAssertEqual(alicesSessionKeys.tx, bobsSessionKeys.rx)
	}

	func testSingleKeyExchange() {
		let alice = KeyExchange(side: .client)
		let bob = KeyExchange(side: .server)

		let alicesSessionKey = alice.sessionKey(for: bob.publicKey)!
		let bobsSessionKey = bob.sessionKey(for: alice.publicKey)!

		KMAssertEqual(alicesSessionKey, bobsSessionKey)
	}

}
