/**
	This class represents hashed passwords. They can be used to store passwords
	for the purpose of authenticating users. Passwords should not be stored as
	plaintext values to avoid compromise if they get in the wrong hands.

	## Example

	```swift
	// 1. The user somehow enters a password
	let userInput = "Correct Horse Battery Staple"
	// 2. You can now indicate that the user input is actually a password.
	// This will copy the password to a secure memory location.
	let password = Password(userInput)!
	// 3. Once you have a password, you can hash it for storing it securely
	// on disk or in a database.
	let hashedPassword = password.hash()
	// 4. The actual value to store, can be derived as follows:
	let valueToStore = hashedPassword.string
	// 5. Now if you want to authenticate a user, the first two steps are
	// equal. You just need to restore the `hashedPassword` from the value
	// previously stored on disk or in a database.
	if hashedPassword.isVerified(by: password) {
	    // The user is authenticated successfully.
	} else {
	    // The user failed to authenticate.
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
	let bytes: Data

	/**
		Constructs a `HashedPassword` instance from a hashed password.

		- parameters:
			- bytes: The hashed password as ASCII decoded string.
	*/
	public init?(_ bytes: Data) {
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
		guard let bytes = string.data(using: .ascii) else {
			return nil
		}
		self.init(bytes)
	}

	/**
		Returns an ASCII encoded representation of the hashed password. This
		value can be securely stored on disk or in a database.
	*/
	public var string: String {
		get {
			/*
				The result of `libsodium.crypto_pwhash_str()` is guaranteed to
				be ASCII-encoded, therefore we can safely force unwrap here.
			*/
			return String(data: bytes, encoding: .ascii)!
		}
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
