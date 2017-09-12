import XCTest
import Tafelsalz

class ExtensionsTest: XCTestCase {

	func testDataExtensions() {
		XCTAssertEqual(Data(hex: "DEADBEEF"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
		XCTAssertEqual(Data(hex: "cafebabe"), Data([0xCA, 0xFE, 0xBA, 0xBE]))
		XCTAssertEqual(Data(hex: "00112233"), Data([0x00, 0x11, 0x22, 0x33]))
		XCTAssertEqual(Data(hex: "X0112233"), Data())
		XCTAssertEqual(Data(hex: ""), Data())
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: ":"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: "-"), Data([0xDE]))
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: ":X"), Data([0xDE, 0xAD, 0xBE, 0xEF]))
		XCTAssertEqual(Data(hex: "DE:AD:XX:BE:EF", ignore: ":X"), Data([0xDE, 0xAD, 0xBE, 0xEF]))

		XCTAssertEqual(Data().hex, "")
		XCTAssertEqual(Data(hex: "DEADBEEF").hex, "deadbeef")
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: "-").hex, "de")
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: ":").hex, "deadbeef")
		XCTAssertEqual(Data(hex: "DE:AD:BE:EF", ignore: ":X").hex, "deadbeef")
		XCTAssertEqual(Data(hex: "DE:AD:XX:BE:EF", ignore: ":X").hex, "deadbeef")
	}

}
