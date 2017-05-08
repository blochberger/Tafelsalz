import libsodium

public struct HashedPassword {
	public static let SizeInBytes = PInt(libsodium.crypto_pwhash_strbytes())

	internal let bytes: Data

	public init?(_ bytes: Data) {
		guard Tafelsalz.isInitialized() else {
			return nil
		}

		guard bytes.count == Int(HashedPassword.SizeInBytes) else {
			return nil
		}

		self.bytes = bytes
	}

	public var string: String {
		get {
			/*
				The result of `libsodium.crypto_pwhash_str()` is guaranteed to
				be ASCII-encoded, therefore we can safely force unwrap here.
			*/
			return String(data: bytes, encoding: .ascii)!
		}
	}

	public func isVerified(by password: Password) -> Bool {
		return password.verifies(self)
	}
}
