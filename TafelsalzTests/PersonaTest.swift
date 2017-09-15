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
		let persona1 = Persona(uniqueName: "Fish")
		let persona2 = Persona(uniqueName: "Chips")

		var masterKey1: MasterKey! = nil
		var masterKey2: MasterKey! = nil
		var secretKey: SecretBox.SecretKey! = nil
		var genericHashKey: GenericHash.Key! = nil

		XCTAssertNoThrow(masterKey1 = try persona1.masterKey())
		XCTAssertNoThrow(secretKey = try persona1.secretKey())
		XCTAssertNoThrow(genericHashKey = try persona1.genericHashKey())
		XCTAssertNoThrow(masterKey2 = try persona2.masterKey())

		XCTAssertEqual(try! persona1.masterKey(), masterKey1)
		XCTAssertEqual(try! Persona(uniqueName: persona1.uniqueName).masterKey(), masterKey1)

		XCTAssertNotEqual(masterKey1, masterKey2)

		XCTAssertNotEqual(masterKey1, secretKey)
		XCTAssertNotEqual(masterKey1, genericHashKey)
		XCTAssertNotEqual(secretKey, genericHashKey)

		XCTAssertNoThrow(try Persona.forget(persona1))
		XCTAssertNoThrow(try Persona.forget(persona2))
	}

}
