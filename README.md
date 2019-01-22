# Tafelsalz

[![Build Status](https://travis-ci.org/blochberger/Tafelsalz.svg?branch=master)](https://travis-ci.org/blochberger/Tafelsalz) [![Coverage](https://blochberger.github.io/Tafelsalz/macos/coverage.svg)](https://blochberger.github.io/Tafelsalz/macos/coverage/index.html) [![Documentation](https://blochberger.github.io/Tafelsalz/macos/public/badge.svg)](https://blochberger.github.io/Tafelsalz)

The main idea of this project is to provide usable but safe cryptographic operations.

The [*libsodium*](https://libsodium.org) project has a similar goal, but does not leverage the features available in modern programming languages such as Swift. The *libsodium* library is based on [NaCl](https://nacl.cr.yp.to) whoose authors discussed the security issues related to cryptographic APIs that are too complicated and error-prone¹ – or as Matthew Green² put it:

> OpenSSL is the space shuttle of crypto libraries. It will get you to space, provided you have a team of people to push the ten thousand buttons required to do so. NaCl is more like an elevator — you just press a button and it takes you there. No frills or options.
>
> I like elevators.

To stay with the analogy: *libsodium* and *NaCl* prevent any accidents to happen if you press a button for some floor which isn't there. This project tries to prevent the button being there in the first place.

This is achieved by leveraging programming language features in a way that an operation cannot be called with invalid or insecure parameters. Every such call should be prevented at compile time already.

Note that the goal is not to prevent malicious attackers to circumvent the established protection mechanisms by the programming language features but to prevent accidental misuse of cryptographic APIs. If you want to learn more about cryptographic misuse, see our [literature collection on cryptographic misuse](https://github.com/blochberger/Tafelsalz/wiki/References#cryptographic-misuse).

- Repository: https://github.com/blochberger/Tafelsalz
- Documentation: https://blochberger.github.io/Tafelsalz
  - macOS: [public](https://blochberger.github.io/Tafelsalz/macos/public), [internal](https://blochberger.github.io/Tafelsalz/macos/internal), [private](https://blochberger.github.io/Tafelsalz/macos/private)
  - iOS: [public](https://blochberger.github.io/Tafelsalz/iphone/public), [internal](https://blochberger.github.io/Tafelsalz/iphone/internal), [private](https://blochberger.github.io/Tafelsalz/iphone/private)
- Issues: https://github.com/blochberger/Tafelsalz/issues

Check out the project with:

```sh
git clone --recursive https://github.com/blochberger/Tafelsalz.git
```

⚠️ **WARNING**: This project will not provide backwards compatibility. The API might change with the purpose of improving it. Changes should stabilize over time. If you need a more backwards compatible framework, I suggest to use [jedisct1/swift-sodium](https://github.com/jedisct1/swift-sodium).

If you simply want to play around with the API, you can try to solve the tasks of the [DCrypt educational stub project](https://github.com/AppPETs/DCrypt).

## Concept

There are several basic ideas:
- Let the compiler catch/enforce as much as possible.
- Avoid common mistakes.
- Combine convenience and security.
- Take care of security-related stuff, that a cryptographic library usually does not, e.g., storing credentials securely on the device.

Note that asymmetric encryption as well as stream encryption are not supported, yet (see https://github.com/blochberger/Tafelsalz/issues/2, https://github.com/blochberger/Tafelsalz/issues/5).

## Features

### Identity Management

There are basically two different kinds of identities or actors: personas and contacts. For personas you are in posession of the secret keys. For contacts you are only in possession of the public keys.

Storing credentials is not as easy as it sounds. Many applications do this wrong and store a password for authenticating a user in plaintext or cryptographic keys alongside the encrypted data. Passwords for authenticating a user must not be stored directly, a salted hash should be stored instead, see *Password Hashing* below. For cryptographic keys it is better to use the credential storage offered by iOS, the [Keychain services](https://developer.apple.com/documentation/security/keychain_services). Credentials stored there are encrypted by the Secure Enclave³. Unfortunately the Keychain services are only accessible by a low-level API, with insufficient documentation by default. Convenience APIs for different tasks have been added.

Personas are app-specific: the bundle identifier of the application is used to distinguish two personas with the same unique name in two different applications. The secrets for personas are automatically generated when they are used for the first time. They are automatically stored in the system's Keychain. If a persona was created earlier, e.g., in a previous session, the keys will be automatically retrieved from the system's Keychain. A `Persona` instance can be created with:

```swift
let alice = Persona(uniqueName: "Alice")
// No secrets are generated until they are actually used.
```

In order to remove all cryptographic keys of that persona, you can tell your application to forget it:

```swift
do {
    try Persona.forget(alice)
} catch {
	// TODO Handle errors, which are either `Persona.Error` or `Keychain.Error`.
}
```

Note that by deleting a persona you will loose access to data encrypted for this persona.

### Symmetric Encryption

#### Ephemeral Keys

```swift
let secretBox = SecretBox()
let plaintext = "Hello, World!".utf8Bytes
let ciphertext = secretBox.encrypt(plaintext: plaintext)
let decrypted = secretBox.decrypt(ciphertext: ciphertext)!
```

#### Persisted Keys

The cryptographic keys in this example are stored within the system's  Keychain. See *Identity Management* for details.

```swift
// Create a persona
let alice = Persona(uniqueName: "Alice")

// Once a secret of that persona is used, it will be persisted in the
// system's Keychain.
let secretBox = SecretBox(persona: alice)!

// Use your SecretBox as usual
let plaintext = "Hello, World!".utf8Bytes
let ciphertext = secretBox.encrypt(plaintext: plaintext)
let decrypted = secretBox.decrypt(ciphertext: ciphertext)!
```

#### Padding

Padding can be used to hide the length of the original message. The size of the ciphertext will be a multiple of the given block size.

Assume you have a client with a known set of possible configurations that are encrypted and stored on a server. If each configuration has a different size, then the server can distinguish the encrypted configurations based on their size. With padding all encrypted configurations can be made indistinguishable by chosing the block size in a way that all encrypted configurations have the same size, by using the size of the largest configuration as block size.

```swift
let secretBox = SecretBox()
let plaintext = "Hello, World!".utf8Bytes
let padding: Padding = .padded(blockSize: 16)
let ciphertext = secretBox.encrypt(plaintext: plaintext, padding: padding)
let decrypted = secretBox.decrypt(ciphertext: ciphertext, padding: padding)!
```

### Password Hashing

If the goal ist to simply authenticate the user, by validating if he knows a previously set password, then this should be used. The password must not be stored directly. A salted hash generated by a password hashing function should be stored instead. That way the actual password is kept secret even if the stored data can be accessed by unauthorized parties.

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

### Generic Hashing

#### Public Hashing

This can be used to create a hash value of a byte sequence that can be used for checking the byte sequences integrity or for proofing that a specific byte sequence is known, without disclosing the byte sequence. This must not be used for storing password hashes, use what is described in *Password Hashing* instead.

```swift
let data = "Hello, World!".utf8Bytes
let hash = GenericHash(bytes: data)
```

#### Private Hashing with Persisted Keys

Private hashing is similar to public hashing, but the hash value cannot be calculated by other parties.

```swift
// Create a persona
let alice = Persona(uniqueName: "Alice")

// Generate a personalized hash for that persona
let data = "Hello, World!".utf8Bytes
let hash = GenericHash(bytes: data, for: alice)

// Forget the persona and remove all related Keychain entries
try! Persona.forget(alice)
```

### Key Derivation

#### Master Key

```swift
let context = MasterKey.Context("Examples")!
let masterKey = MasterKey()
let subKey1 = masterKey.derive(sizeInBytes: MasterKey.DerivedKey.MinimumSizeInBytes, with: 0, and: context)!
let subKey2 = masterKey.derive(sizeInBytes: MasterKey.DerivedKey.MinimumSizeInBytes, with: 1, and: context)!

// You can also derive a key in order to use it with secret boxes
let secretBox = SecretBox(secretKey: masterKey.derive(with: 0, and: context))
```

#### Password

This can be used to derive a cryptographic key from a given password. The API is still work-in-progress and needs to be simplified, see https://github.com/blochberger/Tafelsalz/issues/7.

```swift
let plaintext = "Hello, World!".utf8Bytes
let password = Password("Correct Horse Battery Staple")!

// Derive a new key from a password
let derivedKey1 = password.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes)!
let secretBox1 = SecretBox(secretKey: SecretBox.SecretKey(derivedKey1))
let ciphertext = derivedKey1.publicParameters + secretBox1.encrypt(plaintext: plaintext).bytes

// Derive a previously generated key from a password
let (salt, complexity, memory) = Password.DerivedKey.extractPublicParameters(bytes: ciphertext)!
let derivedKey2 = password.derive(sizeInBytes: SecretBox.SecretKey.SizeInBytes, complexity: complexity, memory: memory, salt: salt)!
let secretBox2 = SecretBox(secretKey: SecretBox.SecretKey(derivedKey2))
let authenticatedCiphertextBytes = Bytes(ciphertext[Int(Password.DerivedKey.SizeOfPublicParametersInBytes)...])
let authenticatedCiphertext = SecretBox.AuthenticatedCiphertext(bytes: authenticatedCiphertextBytes)!
let decrypted = secretBox2.decrypt(ciphertext: authenticatedCiphertext)!
```

### Key Exchange

```swift
let alice = KeyExchange(side: .client)
let bob = KeyExchange(side: .server)

let alicesSessionKey = alice.sessionKey(for: bob.publicKey)
let bobsSessionKey = bob.sessionKey(for: alice.publicKey)

// alicesSessionKey == bobsSessionKey
```

There is a demo application available for iOS, which shows how to exchange secrets between two devices with QR codes, using the key exchange mechanism, see [SecretSharing-iOS](https://github.com/AppPETs/SecretSharing-iOS).

---

1. D. J. Bernstein, T. Lange, and P. Schwabe, [**The Security Impact of a New Cryptographic Library**](http://dx.doi.org/10.1007/978-3-642-33481-8_9) in *Progress in Cryptology – LATINCRYPT 2012 – 2nd International Conference on Cryptology and Information Security in Latin America, Santiago, Chile, October 7-10, 2012. Proceedings* (A. Hevia and G. Neven, eds.), pp. 159–176
2. M. Green, [**The Anatomy of a Bad Idea**](http://blog.cryptographyengineering.com/2012/12/the-anatomy-of-bad-idea.html), 2012
3. Apple Inc., [**iOS Security – iOS 11**](https://www.apple.com/business/docs/iOS_Security_Guide.pdf), 2018
