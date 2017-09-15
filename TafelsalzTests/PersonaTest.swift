import XCTest
@testable import Tafelsalz

class PersonaTest: XCTestCase {

	/**
		- warning:
			The test will actually create an entry in your default Keychain. It
			will remove the entry again, if the test succeeds. In case of
			failure, the entry needs to be manually removed. The name of the
			entry is suffixed with the test bundle's ID. Searching for
			"TafelsalzTests" should suffice.
	*/
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

}
