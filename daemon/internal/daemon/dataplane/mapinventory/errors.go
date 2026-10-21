package mapinventory

import "errors"

// Sentinel errors. Sorted by surface area:
//
//   - ErrUnknownField / ErrFieldType / ErrFieldOverflow are thrown by
//     the codec; kubectl maps them to InvalidArgument.
//   - ErrMapNotFound / ErrInnerKeyMissing / ErrInnerKeyInvalid are
//     thrown by the inventory; kubectl maps them to NotFound or
//     InvalidArgument.
//   - ErrSchemaMismatch is thrown at registration time when a
//     descriptor's declared layout does not match the live map's
//     KeySize/ValueSize. It is a daemon programming error and is
//     intended to crash the daemon at startup so it never ships
//     entries with the wrong layout. ErrPerCPUValue is the same kind of
//     error, for a per-CPU map whose value is not made of counters.
var (
	ErrUnknownField    = errors.New("mapinventory: unknown field")
	ErrFieldType       = errors.New("mapinventory: bad field type")
	ErrFieldOverflow   = errors.New("mapinventory: field value overflow")
	ErrMapNotFound     = errors.New("mapinventory: map not found")
	ErrInnerKeyMissing = errors.New("mapinventory: inner key required for HASH_OF_MAPS")
	ErrInnerKeyInvalid = errors.New("mapinventory: inner key did not match a programmed inner map")
	ErrSchemaMismatch  = errors.New("mapinventory: schema width disagrees with map size")
	ErrPerCPUValue     = errors.New("mapinventory: a per-CPU value must be made of u64 counters")
)
