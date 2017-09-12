import XCTest
@testable import Tafelsalz

/**
	Some tests are based on or taken from the tests performed in
	`jedisct1/swift-sodium`.
**/
class RandomTests: XCTestCase {

	func testBytes() {
		let randomCount = 100 + Random.number(withUpperBound: 100)
		let bytes = Random.bytes(count: randomCount)

		XCTAssertEqual(bytes.count, Int(randomCount))

		let otherBytes = Random.bytes(count: randomCount)

		// Two random byte sequences should not be equal, the probability of
		// that to happen is very low: 1/(2^(randomCount*8)).
		XCTAssertNotEqual(bytes, otherBytes)

		// Two random byte sequences from newly instantiated random generators
		// should not be equal.
		XCTAssertNotEqual(
			Random.bytes(count: randomCount),
			Random.bytes(count: randomCount)
		)
	}

	func testNumberDistribution() {
		var occurrences: UInt = 0
		let referenceNumber = Random.number()
		for _ in 0..<100 {
			if Random.number() == referenceNumber {
				occurrences += 1
			}
		}

		// Test if the reference number occurred more frequently than expected.
		XCTAssert(occurrences < 10)
	}

	func testNumberWithUpperBoundDistribution() {
		let upperBound: UInt32 = 100_000
		var occurrences: UInt = 0
		let referenceNumber = Random.number(withUpperBound: upperBound)
		for _ in 0..<100 {
			if Random.number(withUpperBound: upperBound) == referenceNumber {
				occurrences += 1
			}
		}

		// Test if the reference number occurred more frequently than expected.
		XCTAssert(occurrences < 10)
	}

}
