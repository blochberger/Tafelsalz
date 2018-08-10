/**
	This class is used to securely store values in memory.

	- see: [`libsodium`: Secure memory allocations](https://download.libsodium.org/doc/helpers/memory_management.html)
*/
public class Memory {

	/**
		The size of the memory region in bytes.
	*/
	public let sizeInBytes: UInt32

	/**
		The pointer to the secure memory region.
	*/
	private let pointer: UnsafeMutableRawPointer

	/**
		Allocates a secure memory region. The region is filled with `0xdb`.
	
		- parameters:
			- sizeInBytes: The size of the memory region in bytes.
	*/
	public init(sizeInBytes: UInt32) {
		self.sizeInBytes = sizeInBytes
		self.pointer = sodium.memory.allocate(sizeInBytes: Int(sizeInBytes))

		makeInaccessible()
	}

	/**
		Copies bytes from a byte array to a secure memory location and wipes the
		input.
	
		- parameters:
			- bytes: The byte array.
	*/
	public convenience init(_ bytes: inout Data) {
		self.init(sizeInBytes: UInt32(bytes.count))

		makeReadWritable()
		bytes.withUnsafeBytes { pointer.copyMemory(from: $0, byteCount: bytes.count) }
		makeInaccessible()

		sodium.memory.wipe(&bytes)
	}

	/**
		Deletes secure memory. The memory is overwritten with zeroes.
	*/
	deinit {
		makeReadWritable()
		sodium.memory.free(pointer)
	}

	/**
		Make the memory region read only.
	*/
	private func makeReadOnly() {
		sodium.memory.make_readonly(pointer)
	}

	/**
		Make the memory region writable.
	*/
	private func makeReadWritable() {
		sodium.memory.make_readwritable(pointer)
	}

	/**
		Make the memory region inaccessible.
	*/
	private func makeInaccessible() {
		sodium.memory.make_inaccessible(pointer)
	}

	/**
		Read raw bytes memory region.

		Usually you do not need to call this function.

		- parameters:
			- body: A code block where the memory region is readable.

		- returns: The result from the `body` code block.
	*/
	public func withUnsafeBytes<ResultType, ContentType>(body: (UnsafePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		makeReadOnly()

		let result = try body(UnsafeRawPointer(pointer).bindMemory(to: ContentType.self, capacity: Int(sizeInBytes)))

		makeInaccessible()

		return result
	}

	/**
		Make changes to the raw bytes of the memory region.

		- parameters:
			- body: A code block where the memory region is writable.

		- returns: The result from the `body` code block.
	*/
	func withUnsafeMutableBytes<ResultType, ContentType>(body: (UnsafeMutablePointer<ContentType>) throws -> ResultType) rethrows -> ResultType {
		makeReadWritable()

		let result = try body(UnsafeMutableRawPointer(pointer).bindMemory(to: ContentType.self, capacity: Int(sizeInBytes)))

		makeInaccessible()

		return result
	}
}
