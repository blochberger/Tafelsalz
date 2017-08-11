import XCTest
@testable import Tafelsalz

class GenericHashTest: XCTestCase {

	// MARK: - GenericHash.Key

	func testKey() {
		typealias Key = GenericHash.Key

		let defaultInitializer = { Key() }
		let capturingInitializer: (inout Data) -> Key? = { Key(bytes: &$0) }

		KeyMaterialTest.metaTestDefaultInitializer(of: Key.DefaultSizeInBytes, with: defaultInitializer)
		KeyMaterialTest.metaTestCapturingInitializer(minimumSizeInBytes: Key.MinimumSizeInBytes, maximumSizeInBytes: Key.MaximumSizeInBytes, with: capturingInitializer)
		KeyMaterialTest.metaTestEquality(of: Key.DefaultSizeInBytes, withCapturingInitializer: capturingInitializer)

		XCTAssertNotNil(Key(sizeInBytes: Key.MinimumSizeInBytes))
		XCTAssertNotNil(Key(sizeInBytes: Key.MaximumSizeInBytes))

		XCTAssertNil(Key(sizeInBytes: Key.MinimumSizeInBytes - 1))
		XCTAssertNil(Key(sizeInBytes: Key.MaximumSizeInBytes + 1))

		XCTAssertNotNil(Key(hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
		XCTAssertNotNil(Key(hex: "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f", ignore: ":"))

		XCTAssertNil(Key(hex: "00"))
		XCTAssertNil(Key(hex: "x00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
	}

	// MARK: - GenericHash

	func testGenericHash() {
		typealias Key = GenericHash.Key

		// Testvector taken from https://github.com/BLAKE2/BLAKE2/blob/eec32b7170d8dbe4eb59c9afad2ee9297393fb5b/testvectors/blake2b-kat.txt#L47-L49
		let input = Data(hex: "000102030405060708090a")!
		let key = Key(hex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
		let expectedHash = "f228773ce3f3a42b5f144d63237a72d99693adb8837d0e112a8a0f8ffff2c362857ac49c11ec740d1500749dac9b1f4548108bf3155794dcc9e4082849e2b85b"
		let hash = GenericHash(bytes: input, outputSizeInBytes: GenericHash.MaximumSizeInBytes, with: key)

		XCTAssertNotNil(hash)

		let actualHash = hash!.hex

		XCTAssertNotNil(actualHash)

		XCTAssertEqual(actualHash!, expectedHash)
	}
}