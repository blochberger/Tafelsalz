extension Data {

	/**
		Initialize a byte array from a given hex string.

		- note:
			The byte array will contain the bytes up until the first non-hex
			character, e.g.:

			```swift
			Data(hex: "00XX11").hex == "00"
			Data(hex: "XX").hex == ""
			```

		- parameters:
			- hex: The hex string, e.g., "DEADBEEF", "cafebabe", "00112233"
			- ignore: A set of characters that should be ignored in the hex
				string.
	*/
	public init(hex: String, ignore: String? = nil) {
		self = sodium.hex2bin(hex, ignore: ignore)
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
	public var hex: String {
		return sodium.bin2hex(self)
	}

}
