import libsodium

/**
	If a function can only be called with valid data, there is no need to
	validate the data inside the function. This also eliminates the need to
	return optionals for invalid input data – except for the cases we call other
	functions that might fail, e.g. if a resource is busy or if we lack
	permissions to write to a specified file.

	Unfortunately some function signatures do not follow that principle, e.g.
	the `Data.init(count: Int)` initializer takes an `Int` although a negative
	value for `count` makes no sense. The reason behind this might be to protect
	against overflows or insufficient bytes for other functions provided by the
	same class. E.g. `Data.distance(from: Int, to: Int) -> Int` might return a
	negative value if `to < from` and `Int` is not big enough to express a
	negative distance of `from = UInt.max` and `to = 0`.

	So `Int` it is and wherever it is passed a check is required if a negative
	value makes sense. If that check is forgotten the application will crash.
	Fortunately, since in other programming languages this might lead to invalid
	memory being accessed. This data type allows us to only pass the positive
	part of an `Int`, which is basically half an `UInt` for the current
	architecture.
**/
#if arch(x86_64) || arch(arm64)
	public typealias PInt = UInt32
#else
	public typealias PInt = UInt16
#endif

class Tafelsalz {
	private static let instance = Tafelsalz()

	init?() {
		guard libsodium.sodium_init() == 0 else {
			return nil
		}
	}

	static func isInitialized() -> Bool {
		return instance != nil
	}
}
