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

		XCTAssertNotNil(persona1.secretKey())
		XCTAssertNotNil(persona2.secretKey())

		XCTAssertEqual(persona1.secretKey()!, persona1.secretKey()!)
		XCTAssertEqual(persona1.secretKey()!, Persona(uniqueName: persona1.uniqueName).secretKey()!)

		XCTAssertNotEqual(persona1.secretKey()!, persona2.secretKey()!)

		XCTAssertNoThrow(try Persona.forget(persona1))
		XCTAssertNoThrow(try Persona.forget(persona2))
	}

}
