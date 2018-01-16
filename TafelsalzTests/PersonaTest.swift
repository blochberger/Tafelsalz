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

	func metaTestInvalidKey<T: KeyMaterial>(persona: Persona, type: Persona.KeyType, invalidSize: UInt32? = nil, retrieveKey: (Persona) throws -> T) {
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

		KMAssertEqual(key1, key2)
	}

	func metaTestInitializer<T>(persona: Persona, type: Persona.KeyType, initializer: (Persona) -> T?) {
		// By default it should work
		XCTAssertNotNil(initializer(persona))

		// Set an invalid key
		let item = persona.keychainItem(for: type)
		XCTAssertNoThrow(try Keychain.update(password: Data("😱".utf8), for: item))

		// Now the initializer should fail as well
		XCTAssertNil(initializer(persona))
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

		KMAssertNotEqual(alicesMasterKey, bobsMasterKey)

		KMAssertEqual(try! bob.masterKey(), bobsMasterKey)
		KMAssertEqual(try! Persona(uniqueName: bob.uniqueName).masterKey(), bobsMasterKey)

		KMAssertNotEqual(bobsMasterKey, bobsSecretKey)
		KMAssertNotEqual(bobsMasterKey, bobsGenericHashKey)
		KMAssertNotEqual(bobsSecretKey, bobsGenericHashKey)

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(bob))
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testInvalidKeys() {
		let alice = Persona(uniqueName: "Alice")

		metaTestInvalidKey(persona: alice, type: .masterKey) { try $0.masterKey() }
		metaTestInvalidKey(persona: alice, type: .secretKey) { try $0.secretKey() }
		metaTestInvalidKey(persona: alice, type: .genericHashKey, invalidSize: GenericHash.Key.MinimumSizeInBytes - 1) { try $0.genericHashKey() }

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testNoCache() {
		let alice = Persona(uniqueName: "Alice")

		var masterKey1: MasterKey! = nil
		XCTAssertNoThrow(masterKey1 = try alice.masterKey())

		let item = alice.keychainItem(for: .masterKey)

		XCTAssertNoThrow(try Keychain.delete(item: item))

		var masterKey2: MasterKey! = nil
		XCTAssertNoThrow(masterKey2 = try alice.masterKey())

		KMAssertNotEqual(masterKey1, masterKey2)

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testInitializers() {
		let alice = Persona(uniqueName: "Alice")

		metaTestInitializer(persona: alice, type: .secretKey) { SecretBox(persona: $0) }
		metaTestInitializer(persona: alice, type: .genericHashKey) { GenericHash(bytes: Data("foo".utf8), for: $0) }

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testSettingMasterKey() {
		let alice = Persona(uniqueName: "Alice")
		let key1 = MasterKey()
		let key2 = MasterKey()

		var actualKey: MasterKey! = nil

		// Set a new master key
		XCTAssertNoThrow(try alice.setMasterKey(key1))
		XCTAssertNoThrow(actualKey = try alice.masterKey())
		KMAssertEqual(actualKey, key1)

		actualKey = nil

		// Update an existing master key
		XCTAssertNoThrow(try alice.setMasterKey(key2))
		XCTAssertNoThrow(actualKey = try alice.masterKey())
		KMAssertEqual(actualKey, key2)

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testSettingSecretKey() {
		let alice = Persona(uniqueName: "Alice")
		let key1 = SecretBox.SecretKey()
		let key2 = SecretBox.SecretKey()

		var actualKey: SecretBox.SecretKey! = nil

		// Set a new master key
		XCTAssertNoThrow(try alice.setSecretKey(key1))
		XCTAssertNoThrow(actualKey = try alice.secretKey())
		KMAssertEqual(actualKey, key1)

		actualKey = nil

		// Update an existing master key
		XCTAssertNoThrow(try alice.setSecretKey(key2))
		XCTAssertNoThrow(actualKey = try alice.secretKey())
		KMAssertEqual(actualKey, key2)

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

	func testSettingHashKey() {
		let alice = Persona(uniqueName: "Alice")
		let key1 = GenericHash.Key()
		let key2 = GenericHash.Key()

		var actualKey: GenericHash.Key! = nil

		// Set a new master key
		XCTAssertNoThrow(try alice.setGenericHashKey(key1))
		XCTAssertNoThrow(actualKey = try alice.genericHashKey())
		KMAssertEqual(actualKey, key1)

		actualKey = nil

		// Update an existing master key
		XCTAssertNoThrow(try alice.setGenericHashKey(key2))
		XCTAssertNoThrow(actualKey = try alice.genericHashKey())
		KMAssertEqual(actualKey, key2)

		// Cleanup
		XCTAssertNoThrow(try Persona.forget(alice))
	}

}
