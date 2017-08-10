import libsodium

/**
	This class can be used to securely generate random data.
*/
public class Random {

	/**
		Initialize a secure random data generator.
	*/
	public init?() {
		if !Tafelsalz.isInitialized() {
			return nil
		}
	}

	/**
		Securely generate a random sequence of bytes.

		- parameters:
			- count: The amount of bytes.
	*/
	public func bytes(count: PInt) -> Data {
		let count = Int(count)
		var data = Data(count: count)

		data.withUnsafeMutableBytes {
			dataPtr in

			libsodium.randombytes_buf(dataPtr, count)
		}

		return data
	}

	/**
		Securely generate a random number.
	*/
	public func number() -> UInt32 {
		return libsodium.randombytes_random()
	}

	/**
		Securely generate a random number with a given upper bound. The result
		has a uniform distribution in the Range of `0..upperBound`.

		- parameter:
			-upperBound: The upper bound.
	**/
	public func number(withUpperBound upperBound: UInt32) -> UInt32 {
		return libsodium.randombytes_uniform(upperBound)
	}
}
