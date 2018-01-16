extension Data {

	/**
		Initialize a byte array from a given hex string.

		- parameters:
			- hex: The hex string, e.g., "DEADBEEF", "cafebabe", "00112233"
			- ignore: A set of characters that should be ignored in the hex
				string.
	*/
	public init?(hex: String, ignore: String? = nil) {
		guard let result = sodium.hex2bin(hex, ignore: ignore) else {
			return nil
		}

		self = result
	}

	/**
		Outputs a hex encoded string for the byte array.

		- postcondition: `data` = `Data(hex: data.hex)`
	*/
	public var hex: String {
		return sodium.bin2hex(self)
	}

}
