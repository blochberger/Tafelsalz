import XCTest

import Tafelsalz

class MasterKeyTest: XCTestCase {

	func metaTestDerivation<T: KeyMaterial>(mk: MasterKey, derive: (MasterKey, UInt64, MasterKey.Context) -> T) {
		typealias Context = MasterKey.Context

		let ctx = Context("testtest")!

		let sk1 = derive(mk, 0, ctx)
		let sk2 = derive(mk, 0, ctx)
		let sk3 = derive(mk, 1, ctx)
		let sk4 = derive(mk, 0, Context("Testtest")!)

		KMAssertEqual(sk1, sk2)
		KMAssertNotEqual(sk1, sk3)
		KMAssertNotEqual(sk1, sk4)
		KMAssertNotEqual(sk3, sk4)
	}

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

		KeyMaterialTest.metaTestDefaultInitializer(of: MasterKey.SizeInBytes, eq: { $0.copyBytes() }, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(of: MasterKey.SizeInBytes, eq: { $0.copyBytes() }, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: MasterKey.SizeInBytes, withCapturingInitializer: capturingInitializer)
	}

	func testKeyDerivation() {
		typealias Context = MasterKey.Context
		typealias DerivedKey = MasterKey.DerivedKey

		let mk = MasterKey()

		metaTestDerivation(mk: mk) {
			$0.derive(sizeInBytes: DerivedKey.MinimumSizeInBytes, with: $1, and: $2)!
		}

		let ctx = Context("testtest")!
		XCTAssertNil(mk.derive(sizeInBytes: DerivedKey.MinimumSizeInBytes - 1, with: 0, and: ctx))
		XCTAssertNil(mk.derive(sizeInBytes: DerivedKey.MaximumSizeInBytes + 1, with: 0, and: ctx))
	}

	func testSecretKeyDerivation() {
		metaTestDerivation(mk: MasterKey()) {
			$0.derive(with: $1, and: $2)!
		}
	}

	func testGenericHashKeyDerivation() {
		typealias Context = MasterKey.Context
		typealias DerivedKey = MasterKey.DerivedKey
		typealias Key = GenericHash.Key

		let mk = MasterKey()

		metaTestDerivation(mk: MasterKey()) {
			$0.derive(with: $1, and: $2)!
		}

		let ctx = Context("testtest")!
		XCTAssertNil(mk.derive(sizeInBytes: Key.MinimumSizeInBytes - 1, with: 0, and: ctx))
		XCTAssertNil(mk.derive(sizeInBytes: Key.MaximumSizeInBytes + 1, with: 0, and: ctx))
	}

}
