# Tafelsalz

![Coverage](https://blochberger.github.io/Tafelsalz/macos/coverage.svg) [![Documentation](https://blochberger.github.io/Tafelsalz/macos/public/badge.svg)](https://blochberger.github.io/Tafelsalz)

The main idea of this project is to provide usable but safe cyryptographic operations. Usability does not mean, that the minimum effort is required to integrate an operation. Minimum effort might result in single lines of code that you write… et voilà your system is secure. No. It means that it requires only the minimum of knowledge to do something wrong.

The [*libsodium*](https://libsodium.org) project has a similar goal, but does not leverage the features available in modern programming languages such as Swift. The *libsodium* library is based on [NaCl](https://nacl.cr.yp.to) whoose authors discussed the security issues related to cryptographic APIs that are too complicated and error-prone¹ – or as Matthew Green² put it:

> OpenSSL is the space shuttle of crypto libraries. It will get you to space, provided you have a team of people to push the ten thousand buttons required to do so. NaCl is more like an elevator — you just press a button and it takes you there. No frills or options.
>
> I like elevators.

To stay with the analogy: *libsodium* and *NaCl* prevent any accidents to happen if you press a button for some floor which isn't there. This project tries to prevent the button being there in the first place.

This is achieved by leveraging programming language features in a way that an operation cannot be called with invalid or insecure parameters. Every such call should be prevented at compile time already.

Note that the goal is not to prevent malicious attackers to circumvent the established protection mechanisms by the programming language features but to prevent accidental misuse of cryptographic APIs.

- Repository: https://github.com/blochberger/Tafelsalz
- Documentation: https://blochberger.github.io/Tafelsalz
  - macOS: [public](https://blochberger.github.io/Tafelsalz/macos/public), [internal](https://blochberger.github.io/Tafelsalz/macos/internal), [private](https://blochberger.github.io/Tafelsalz/macos/private)
  - iOS: [public](https://blochberger.github.io/Tafelsalz/iphone/public), [internal](https://blochberger.github.io/Tafelsalz/iphone/internal), [private](https://blochberger.github.io/Tafelsalz/iphone/private)
- Issues: https://github.com/blochberger/Tafelsalz/issues

Check out the project with:

```sh
git clone --recursive https://github.com/blochberger/Tafelsalz.git
```

⚠️ **WARNING**: This project is still work in progress and the API is highly unstable. It is recommended to use a more stable library for the time being, such as [jedisct1/swift-sodium](https://github.com/jedisct1/swift-sodium).

## Concept

There are several basic ideas:
- Let the compiler catch/enforce as much as possible.
- Avoid common mistakes.
- Combine convenience and security.

### Identity Management
There are basically two different kinds of identities or actors: personas and contacts. For personas you are in posession of the secret keys. For contacts you are only in possession of the public keys.

### Persistence of Secrets

The secrets for personas are automatically persisted in the system's Keychain. This is the place, where you want to store your secrets, as storing them in the file system might lead to them being compromised easily.

## Examples

### Symmetric Encryption

#### Ephemeral Keys

```swift
let secretBox = SecretBox()!
let plaintext = "Hello, World!".data(using: .utf8)!
let ciphertext = secretBox.encrypt(data: plaintext)!
let decrypted = secretBox.decrypt(data: ciphertext)!
```

#### Persisted Keys

```swift
// Create a persona
let alice = Persona(uniqueName: "Alice")

// Once a secret of that persona is used, it will be persisted in the
// system's Keychain.
let secretBox = SecretBox(persona: alice)!

// Use your SecretBox as usual
let plaintext = "Hello, World!".data(using: .utf8)!
let ciphertext = secretBox.encrypt(data: plaintext)!
let decrypted = secretBox.decrypt(data: ciphertext)!

// Forget the persona and remove all related Keychain entries
try! Persona.forget(alice)
```

### Password Hashing

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

```swift
let data = "Hello, World!".data(using: .utf8)!
let hash = GenericHash(bytes: data)
```

#### Private Hashing with Persistent Keys

```swift
// Create a persona
let alice = Persona(uniqueName: "Alice")

// Generate a personalized hash for that persona
let data = "Hello, World!".data(using: .utf8)!
let hash = GenericHash(bytes: data, for: alice)

// Forget the persona and remove all related Keychain entries
try! Persona.forget(alice)
```

---

1. D. J. Bernstein, T. Lange, and P. Schwabe, [**The Security Impact of a New Cryptographic Library**](http://dx.doi.org/10.1007/978-3-642-33481-8_9) in *Progress in Cryptology – LATINCRYPT 2012 – 2nd International Conference on Cryptology and Information Security in Latin America, Santiago, Chile, October 7-10, 2012. Proceedings* (A. Hevia and G. Neven, eds.), pp. 159–176
2. M. Green, [**The Anatomy of a Bad Idea**](http://blog.cryptographyengineering.com/2012/12/the-anatomy-of-bad-idea.html), 2012
