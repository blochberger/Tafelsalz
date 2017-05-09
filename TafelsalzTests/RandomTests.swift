import XCTest
@testable import Tafelsalz

/**
	Some tests are based on or taken from the tests performed in
	`jedisct1/swift-sodium`.
**/
class RandomTests: XCTestCase {

    func testInitializer() {
		XCTAssertNotNil(Random())
    }

	func testBytes() {
		let random = Random()!
		let randomCount = 100 + random.number(withUpperBound: 100)
		let bytes = random.bytes(count: randomCount)

		XCTAssertEqual(bytes.count, Int(randomCount))

		let otherBytes = random.bytes(count: randomCount)

		// Two random byte sequences should not be equal, the probability of
		// that to happen is very low: 1/(2^(randomCount*8)).
		XCTAssertNotEqual(bytes, otherBytes)

		// Two random byte sequences from newly instantiated random generators
		// should not be equal.
		XCTAssertNotEqual(
			Random()!.bytes(count: randomCount),
			Random()!.bytes(count: randomCount)
		)
	}

	func testNumberDistribution() {
		let random = Random()!
		var occurrences: UInt = 0
		let referenceNumber = random.number()
		for _ in 0..<100 {
			if random.number() == referenceNumber {
				occurrences += 1
			}
		}

		// Test if the reference number occurred more frequently than expected.
		XCTAssert(occurrences < 10)
	}

	func testNumberWithUpperBoundDistribution() {
		let upperBound: UInt32 = 100_000
		let random = Random()!
		var occurrences: UInt = 0
		let referenceNumber = random.number(withUpperBound: upperBound)
		for _ in 0..<100 {
			if random.number(withUpperBound: upperBound) == referenceNumber {
				occurrences += 1
			}
		}

		// Test if the reference number occurred more frequently than expected.
		XCTAssert(occurrences < 10)
	}
}
