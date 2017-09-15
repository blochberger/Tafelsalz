import XCTest

import Keychain

@testable import Tafelsalz

/**
	- warning:
		These tests will actually create an entry in your default Keychain. It
		will remove the entry again, if the test succeeds. In case of failure,
		the entry needs to be manually removed. The name of the entry is
		suffixed with the test bundle's ID. Searching for "TafelsalzTests"
		should suffice.
*/
class PersonaTest: XCTestCase {

	func metaTestInvalidKey<T: KeyMaterial>(persona: Persona, type: Persona.KeyType, invalidSize: PInt? = nil, retrieveKey: (Persona) throws -> T) {
		var key1: T! = nil
		XCTAssertNoThrow(key1 = try retrieveKey(persona))

		let item = persona.keychainItem(for: type)

		// Set an invalid key
		let invalidKey = Random.bytes(count: invalidSize == nil ? key1.sizeInBytes - 1 : invalidSize!)
		XCTAssertNoThrow(try Keychain.update(password: invalidKey.base64EncodedData(), for: item))

		XCTAssertThrowsError(try retrieveKey(persona)) {
			XCTAssertEqual($0 as! Persona.Error, Persona.Error.invalidKey)
		}

		// Set a key thath is not Base64-encoded
		XCTAssertNoThrow(try Keychain.update(password: Data("😱".utf8), for: item))

		XCTAssertThrowsError(try retrieveKey(persona)) {
			XCTAssertEqual($0 as! Persona.Error, Persona.Error.failedToDecodeKey)
		}

		// Manually set a valid key
		XCTAssertNoThrow(try Keychain.update(password: key1.copyBytes().base64EncodedData(), for: item))

		var key2: T! = nil
		XCTAssertNoThrow(key2 = try retrieveKey(persona))

		XCTAssertEqual(key1, key2)
	}

	func testPersona() {
		let alice = Persona(uniqueName: "Alice")
		let bob = Persona(uniqueName: "Bob")

		var alicesMasterKey: MasterKey! = nil
		var bobsMasterKey: MasterKey! = nil
		var bobsSecretKey: SecretBox.SecretKey! = nil
		var bobsGenericHashKey: GenericHash.Key! = nil

		XCTAssertNoThrow(alicesMasterKey = try alice.masterKey())
		XCTAssertNoThrow(bobsMasterKey = try bob.masterKey())
		XCTAssertNoThrow(bobsSecretKey = try bob.secretKey())
		XCTAssertNoThrow(bobsGenericHashKey = try bob.genericHashKey())

		XCTAssertNotEqual(alicesMasterKey, bobsMasterKey)

		XCTAssertEqual(try! bob.masterKey(), bobsMasterKey)
		XCTAssertEqual(try! Persona(uniqueName: bob.uniqueName).masterKey(), bobsMasterKey)

		XCTAssertNotEqual(bobsMasterKey, bobsSecretKey)
		XCTAssertNotEqual(bobsMasterKey, bobsGenericHashKey)
		XCTAssertNotEqual(bobsSecretKey, bobsGenericHashKey)

		XCTAssertNoThrow(try Persona.forget(bob))
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testInvalidKeys() {
		let alice = Persona(uniqueName: "Alice")

		metaTestInvalidKey(persona: alice, type: .masterKey) { try $0.masterKey() }
		metaTestInvalidKey(persona: alice, type: .secretKey) { try $0.secretKey() }
		metaTestInvalidKey(persona: alice, type: .genericHashKey, invalidSize: GenericHash.Key.MinimumSizeInBytes - 1) { try $0.genericHashKey() }

		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testNoCache() {
		let alice = Persona(uniqueName: "Alice")

		var masterKey1: MasterKey! = nil
		XCTAssertNoThrow(masterKey1 = try alice.masterKey())

		let item = alice.keychainItem(for: .masterKey)

		XCTAssertNoThrow(try Keychain.delete(item: item))

		var masterKey3: MasterKey! = nil
		XCTAssertNoThrow(masterKey3 = try alice.masterKey())

		XCTAssertNotEqual(masterKey1, masterKey3)

		XCTAssertNoThrow(try Persona.forget(alice))
	}

}
