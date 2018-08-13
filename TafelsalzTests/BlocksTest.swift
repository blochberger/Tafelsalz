import XCTest
import Tafelsalz

class BlocksTest: XCTestCase {

	func testInvalidInitializers() {
		XCTAssertNil(Blocks(unpadded: [], blockSize: 0))
		XCTAssertNil(Blocks(padded: [], blockSize: 0))
		XCTAssertNil(Blocks(padded: [0x00], blockSize: 2))
		XCTAssertNil(Blocks(padded: [0x00, 0x00, 0x00], blockSize: 2))

		// Invalid padding
		XCTAssertNil(Blocks(padded: [0x00, 0x00], blockSize: 1))
	}

	func testPadding() {
		let blocks1 = Blocks(unpadded: [], blockSize: 16)!
		XCTAssertEqual(blocks1.blockSize, 16)
		XCTAssertEqual(blocks1.bytes.count, 16)
		XCTAssertEqual(blocks1.withoutPadding, [])

		let unpadded = Random.bytes(count: 16)
		let blocks2 = Blocks(unpadded: unpadded, blockSize: 16)!
		XCTAssertEqual(blocks2.blockSize, 16)
		XCTAssertEqual(blocks2.bytes.count, 32)
		XCTAssertEqual(blocks2.withoutPadding, unpadded)

		let blocks3 = Blocks(padded: blocks2.bytes, blockSize: 16)!
		XCTAssertEqual(blocks3.blockSize, 16)
		XCTAssertEqual(blocks3.bytes.count, 32)
		XCTAssertEqual(blocks3.withoutPadding, unpadded)
	}

}
