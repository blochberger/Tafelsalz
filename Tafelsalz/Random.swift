import libsodium

class Random {

	public init?() {
		if !Tafelsalz.isInitialized() {
			return nil
		}
	}

	public func bytes(count: PInt) -> Data {
		let count = Int(count)
		var data = Data(count: count)

		data.withUnsafeMutableBytes {
			dataPtr in

			libsodium.randombytes_buf(dataPtr, count)
		}

		return data
	}

	public func number() -> UInt32 {
		return libsodium.randombytes_random()
	}

	/**
		Result has uniform distribution in the Range of `0..upperBound`.
	**/
	public func number(withUpperBound upperBound: UInt32) -> UInt32 {
		return libsodium.randombytes_uniform(upperBound)
	}
}
