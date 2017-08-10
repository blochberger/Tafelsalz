/**
	To avoid accidental confusion if data is encrypted or not, this protocol can
	be used to indicate that a data object is encrypted. The actual encrypted
	bytes can be retrieved by accessing `bytes`. In contrast to `Ciphertext`
	classes or structs deriving from `EncryptedData` can contain additinal
	information such as a message authentication code et cetera.
*/
public protocol EncryptedData {

	/**
		The encrypted bytes.
	*/
	var bytes: Data { get }
}
