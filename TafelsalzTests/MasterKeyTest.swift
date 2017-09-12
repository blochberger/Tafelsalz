import XCTest

import Tafelsalz

extension MasterKey.DerivedKey: Equatable {
	public static func ==(lhs: MasterKey.DerivedKey, rhs: MasterKey.DerivedKey) -> Bool {
		return lhs.copyBytes() == rhs.copyBytes()
	}
}

class MasterKeyTest: XCTestCase {

	// MARK: Context

	func testContext() {
		typealias Context = MasterKey.Context

		XCTAssertNotNil(Context("Examples"))
		XCTAssertNotNil(Context(Random.bytes(count: Context.SizeInBytes)))

		XCTAssertNil(Context(Random.bytes(count: Context.SizeInBytes - 1)))
		XCTAssertNil(Context(Random.bytes(count: Context.SizeInBytes + 1)))
	}

	// MARK: MasterKey

	func testMasterKeyInitializer() {
		let defaultInitializer = { MasterKey() }
		let capturingInitializer: (inout Data) -> MasterKey? = { MasterKey(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: MasterKey.SizeInBytes, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: MasterKey.SizeInBytes, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: MasterKey.SizeInBytes, withCapturingInitializer: capturingInitializer)
	}

	func testKeyDerivation() {
		typealias Context = MasterKey.Context
		typealias DerivedKey = MasterKey.DerivedKey

		let size = DerivedKey.MinimumSizeInBytes

		let mk = MasterKey()
		let ctx = Context("testtest")!

		let sk1 = mk.derive(sizeInBytes: size, with: 0, and: ctx)!
		let sk2 = mk.derive(sizeInBytes: size, with: 0, and: ctx)!
		let sk3 = mk.derive(sizeInBytes: size, with: 1, and: ctx)!
		let sk4 = mk.derive(sizeInBytes: size, with: 0, and: Context("Testtest")!)!

		XCTAssertEqual(sk1, sk2)
		XCTAssertNotEqual(sk1, sk3)
		XCTAssertNotEqual(sk1, sk4)
		XCTAssertNotEqual(sk3, sk4)

		XCTAssertNil(mk.derive(sizeInBytes: DerivedKey.MinimumSizeInBytes - 1, with: 0, and: ctx))
		XCTAssertNil(mk.derive(sizeInBytes: DerivedKey.MaximumSizeInBytes + 1, with: 0, and: ctx))
	}

}
