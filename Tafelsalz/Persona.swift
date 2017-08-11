import Foundation
import Keychain

/**
	A persona is an entity for which you are in posession of the secrets. The
	secrets are persisted in the system's Keychain. A persona has a unique name.

	The Keychain items are prefixed by the application's bundle identifier and
	suffixed with a value determining the kind of secret stored.

	The actual value of the secret is Base64 encoded to allow users accessing
	the value from the Keychain Access application (macOS)

	- note:
		The persona is unique per device and application bundle identifier. If
		you create two personas with equal names on two different applications
		or devices, they cannot be used to decrypt secrets of one another. If a
		persona is removed and re-created with the same name, it cannot be used
		to decrypt values encrypted for the previous one.
*/
public class Persona {

	/**
		Forget a persona. This will remove all secrets of this persona from the
		system's Keychain.

		- warning: Removing a persona will delete all secrets of that persona
			which also means, that encrypted messages or files encrypted for
			this persona cannot be decrypted anymore.

		- parameters:
			- persona: The persona that should be deleted.
	*/
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

	/**
		The unique name of the persona.
	*/
	public let uniqueName: String

	/**
		Create a new persona. If the persona was created before, the secrets
		will be retrieved from the system's Keychain.

		- parameters:
			- uniqueName: A name that is unique for that persona.
	*/
	public init(uniqueName: String) {
		self.uniqueName = uniqueName
	}

	/**
		Secrets are persisted in the system's Keychain.

		- returns: The secret key.
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

	/**
		This is used to identify the type of the key.
	*/
	private enum Kind: String {
		/**
			This identifies secret keys that can be used with the secret box.
		*/
		case secretKey = "SecretBox.SecretKey"
	}

	/**
		This is the bundle identifier of the application. It is used to identify
		the service of the password item in the system's Keychain.
	*/
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

	/**
		This constructs an identifier for the service and type of key.

		- parameters:
			- kind: The type of the key.

		- returns: The identifier.
	*/
	private func itemService(kind: Kind) -> String {
		return bundleIdentifier + "/" + kind.rawValue
	}

	/**
		This identifies the Keychain entry for the secret key of this persona.
	*/
	private var secretKeyItem: GenericPasswordItem {
		get {
			return GenericPasswordItem(for: itemService(kind: .secretKey), using: uniqueName)
		}
	}

	/**
		This is an array that holds all Keychain entries for this persona.
	*/
	private var keychainItems: [KeychainItem] {
		get {
			return [secretKeyItem]
		}
	}
}
