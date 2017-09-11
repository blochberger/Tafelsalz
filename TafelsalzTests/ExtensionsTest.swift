import XCTest
import Tafelsalz

class ExtensionsTest: XCTestCase {

	func testDataExtensions() {
		XCTAssertNotNil(Data(hex: "DEADBEEF"))
		XCTAssertNotNil(Data(hex: "cafebabe"))
		XCTAssertNotNil(Data(hex: "00112233"))
		XCTAssertNotNil(Data(hex: "X0112233"))
		XCTAssertNotNil(Data(hex: "DE:AD:BE:EF", ignore: ":"))
		XCTAssertNotNil(Data(hex: "DE:AD:BE:EF", ignore: "-"))
		XCTAssertNotNil(Data(hex: "DE:AD:BE:EF", ignore: ":X"))
		XCTAssertNotNil(Data(hex: "DE:AD:XX:BE:EF", ignore: ":X"))

		XCTAssertEqual("deadbeef", Data(hex: "DEADBEEF").hex)
		XCTAssertEqual(Data(hex: "X0112233"), Data())
		XCTAssertEqual("de", Data(hex: "DE:AD:BE:EF", ignore: "-").hex)
		XCTAssertEqual("deadbeef", Data(hex: "DE:AD:BE:EF", ignore: ":").hex)
		XCTAssertEqual("deadbeef", Data(hex: "DE:AD:BE:EF", ignore: ":X").hex)
		XCTAssertEqual("deadbeef", Data(hex: "DE:AD:XX:BE:EF", ignore: ":X").hex)
		XCTAssertEqual("", Data().hex)
		XCTAssertEqual(Data(hex: ""), Data())
	}

}
