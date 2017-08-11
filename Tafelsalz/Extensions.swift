import Foundation

import libsodium

extension Data {

	/**
		Initialize a byte array from a given hex string.
	
		- note:
			The byte array will contain the bytes up until the first non-hex
			character, e.g.:
	
			```swift
			Data(hex: "00XX11").hex == 00
			Data(hex: "XX").hex == ""
			```
	
		- parameters:
			- hex: The hex string, e.g., "DEADBEEF", "cafebabe", "00112233"
			- ignore: A set of characters that should be ignored in the hex
				string.
	*/
	public init?(hex: String, ignore: String? = nil) {
		// More or less taken from https://github.com/jedisct1/swift-sodium/blob/6845200f10954a1514c162a70e480273886e8318/Sodium/Utils.swift#L84-L122

		guard var hexData = hex.data(using: .utf8, allowLossyConversion: false) else {
			return nil
		}

		let hexDataLen = hexData.count
		let binDataCapacity = hexDataLen / 2
		self.init(count: binDataCapacity)
		var binDataLen: size_t = 0
		let ignore_cstr = ignore != nil ? (ignore! as NSString).utf8String : nil

		let success = withUnsafeMutableBytes { binPtr in
			return hexData.withUnsafeMutableBytes { hexPtr in
				return sodium_hex2bin(
					binPtr,
				    binDataCapacity,
				    hexPtr,
				    hexDataLen,
				    ignore_cstr,
				    &binDataLen,
				    nil
				) == 0
			}
		}

		guard success else { return nil }

		count = Int(binDataLen)
	}

	/**
		Outputs a hex encoded string for the byte array.

		- postcondition:
			This value can be used to duplicate the array, by using the
			`init(hex:)` initializer:

			```swift
			data == Data(hex: data.hex)
			```
	*/
	public var hex: String? {
		// More or less taken from https://github.com/jedisct1/swift-sodium/blob/6845200f10954a1514c162a70e480273886e8318/Sodium/Utils.swift#L64-L82

		let sizeOfResultInBytes = (count * 2) + 1
		var result = Data(count: sizeOfResultInBytes)
		return result.withUnsafeMutableBytes {
			(resultPtr: UnsafeMutablePointer<Int8>) -> String? in

			return withUnsafeBytes {
				(bytesPtr: UnsafePointer<UInt8>) -> String? in

				guard let output = libsodium.sodium_bin2hex(resultPtr, sizeOfResultInBytes, bytesPtr, count) else {
					return nil
				}

				return String(validatingUTF8: output)
			}
		}
	}
}
