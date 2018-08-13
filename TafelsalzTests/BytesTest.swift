import XCTest
import Tafelsalz

class BytesTest: XCTestCase {

	func testHex() {
		XCTAssertEqual("DEADBEEF".unhexlify(), [0xDE, 0xAD, 0xBE, 0xEF])
		XCTAssertEqual("cafebabe".unhexlify(), [0xCA, 0xFE, 0xBA, 0xBE])
		XCTAssertEqual("00112233".unhexlify(), [0x00, 0x11, 0x22, 0x33])
		XCTAssertEqual("".unhexlify(), [])
		XCTAssertEqual("DE:AD:BE:EF".unhexlify(ignore: ":"), [0xDE, 0xAD, 0xBE, 0xEF])
		XCTAssertEqual("DE:AD:BE:EF".unhexlify(ignore: ":X"), [0xDE, 0xAD, 0xBE, 0xEF])
		XCTAssertEqual("DE:AD:XX:BE:EF".unhexlify(ignore: ":X"), [0xDE, 0xAD, 0xBE, 0xEF])

		XCTAssertNil("X0112233".unhexlify())
		XCTAssertNil("DE:AD:BE:EF".unhexlify(ignore: "-"))

		XCTAssertEqual([].hexlify, "")
		XCTAssertEqual("DEADBEEF".unhexlify()!.hexlify, "deadbeef")

		XCTAssertEqual("DE:AD:BE:EF".unhexlify(ignore: ":")!.hexlify, "deadbeef")
		XCTAssertEqual("DE:AD:BE:EF".unhexlify(ignore: ":X")!.hexlify, "deadbeef")
		XCTAssertEqual("DE:AD:XX:BE:EF".unhexlify(ignore: ":X")!.hexlify, "deadbeef")
	}

	func testBase64() {
		XCTAssertNil(":".b64decode())

		XCTAssertEqual(Data("foo".utf8).base64EncodedString(), "Zm9v")

		XCTAssertEqual("Zm9v".b64decode()!, [0x66, 0x6F, 0x6F])
		XCTAssertEqual([0x66, 0x6F, 0x6F].b64encode(), "Zm9v")
		XCTAssertEqual("Zm9v".b64decode()!.b64encode(), "Zm9v")
		XCTAssertEqual("Z:m9::v".b64decode(ignore: ":")!, [0x66, 0x6F, 0x6F])

		let bytes = Random.bytes(count: 32)
		XCTAssertEqual(bytes.b64encode().b64decode()!, bytes)
	}

}
