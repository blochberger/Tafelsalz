/**
	This class represents hashed passwords. They can be used to store passwords
	for the purpose of authenticating users. Passwords should not be stored as
	plaintext values to avoid compromise if they get in the wrong hands.

	## Example

	```swift
	let password = Password("Correct Horse Battery Staple")!
	let hashedPassword = password.hash()!

	// Store `hashedPassword.string` to database.

	// If a user wants to authenticate, just read it from the database and
	// verify it against the password given by the user.
	if hashedPassword.isVerified(by: password) {
	    // The user is authenticated successfully.
	}
	```
*/
public struct HashedPassword {
	/**
		The size of the hashed password string in bytes. As the string is ASCII
		encoded it will match the number of characters.
	*/
	public static let SizeInBytes = UInt32(sodium.pwhash.sizeOfStorableStringInBytes)

	/**
		The hashed password.
	*/
	let bytes: Bytes

	/**
		Constructs a `HashedPassword` instance from a hashed password.

		- parameters:
			- bytes: The hashed password as ASCII decoded string.
	*/
	public init?(_ bytes: Bytes) {
		guard bytes.count == Int(HashedPassword.SizeInBytes) else {
			return nil
		}

		guard String(bytes: bytes, encoding: .nonLossyASCII) != nil else {
			return nil
		}

		self.bytes = bytes
	}

	/**
		Construct a `HashedPassword` instance from a hashed password string.

		- parameters:
			- string: The hashed password as ASCII encoded string.
	*/
	public init?(_ string: String) {
		guard string.data(using: .ascii) != nil else {
			return nil
		}

		self.init(string.utf8Bytes)
	}

	/**
		Returns an ASCII encoded representation of the hashed password. This
		value can be securely stored on disk or in a database.
	*/
	public var string: String {
		/*
			The result of `libsodium.crypto_pwhash_str()` is guaranteed to
			be ASCII-encoded, therefore we can safely force unwrap here.
		*/
		return String(bytes: bytes, encoding: .ascii)!
	}

	/**
		Check if the password `password` authenticates the hashed password.

		- parameters:
			- password: The password, the user is trying to authenticate with.
	*/
	public func isVerified(by password: Password) -> Bool {
		return password.verifies(self)
	}
}
