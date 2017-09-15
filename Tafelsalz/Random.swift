/**
	This can be used to securely generate random data.
*/
public struct Random {

	/**
		Securely generate a random sequence of bytes.

		- parameters:
			- count: The amount of bytes.
	*/
	public static func bytes(count: PInt) -> Data {
		return sodium.random.bytes(count: Int(count))
	}

	/**
		Securely generate a random number.
	*/
	public static func number() -> UInt32 {
		return sodium.random.number()
	}

	/**
		Securely generate a random number with a given upper bound. The result
		has a uniform distribution in the Range of `0..upperBound`.

		- parameters:
			-upperBound: The upper bound.
	**/
	public static func number(withUpperBound upperBound: UInt32) -> UInt32 {
		return sodium.random.uniform(upperBound: upperBound)
	}

}
