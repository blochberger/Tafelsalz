import Foundation
import Keychain

public class Persona {

	public static func forget(_ persona: Persona) throws {
		for item in persona.keychainItems {
			do {
				try Keychain.delete(item: item)
			} catch Keychain.Error.itemNotFound {
				// Ignore non-existing items
			} catch {
				throw error
			}
		}
	}

	public let uniqueName: String

	public init(uniqueName: String) {
		self.uniqueName = uniqueName
	}

	/**
		Secrets are persisted in the system's Keychain.
	
		The Keychain item is prefixed by the application's bundle identifier and
		suffixed with a value determining the kind of secret stored.
	
		The actual value of the secret is Base64 encoded to allow users
		accessing the value from the Keychain Access application (macOS).
	*/
	func secret() -> SecretBox.SecretKey? {
		do {
			// Try to read the secret key from the Keychain
			let encodedSecretKey = try Keychain.retrievePassword(for: secretKeyItem)

			guard var secretKeyBytes = Data(base64Encoded: encodedSecretKey) else {
				return nil
			}

			guard let secretKey = SecretBox.SecretKey(bytes: &secretKeyBytes) else {
				return nil
			}

			return secretKey
		} catch Keychain.Error.itemNotFound {
			// If there is no secret key stored in the Keychain, create a new
			// one and add it to the Keychain.
			guard let secretKey = SecretBox.SecretKey() else {
				return nil
			}

			do {
				try Keychain.store(password: secretKey.copyBytes().base64EncodedData(), in: secretKeyItem)
				return secretKey
			} catch {
				// There was an error when trying to store the secret key to the
				// Keychain.
				return nil
			}
		} catch {
			// There was an error when trying to read the secret key from the
			// Keychain.
			return nil
		}
	}

	private enum Kind: String {
		case secretKey = "SecretBox.SecretKey"
	}

	private var bundleIdentifier: String {
		guard Bundle.main.bundleIdentifier == nil else {
			return Bundle.main.bundleIdentifier!
		}

		for bundle in Bundle.allBundles {
			guard bundle.bundleIdentifier == nil else {
				return bundle.bundleIdentifier!
			}
		}

		return ""
	}

	private func itemService(kind: Kind) -> String {
		return bundleIdentifier + "/" + kind.rawValue
	}

	private var secretKeyItem: GenericPasswordItem {
		get {
			return GenericPasswordItem(for: itemService(kind: .secretKey), using: uniqueName)
		}
	}

	private var keychainItems: [KeychainItem] {
		get {
			return [secretKeyItem]
		}
	}
}
