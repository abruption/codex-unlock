# Lossless file identity snapshots

Lock and transcript observations request Node's `BigIntStats` before creating a
public snapshot. Device and inode identities remain decimal strings, including
values above JavaScript's safe integer limit. Converting a rounded numeric inode
to a string or to `BigInt` cannot recover its original value.

The JSON v1 snapshot shape is unchanged. Mode, UID, link count, and byte size are
numbers only when they are safe, non-negative integers. An unrepresentable value
throws; lock observations become `unknown`, transcript inspection becomes
`unreadable`, and stable hashing rejects rather than claiming stability.

`modifiedMs` remains fractional milliseconds as a number. BigInt nanoseconds are
split into integer milliseconds and a fractional remainder instead of using the
truncated BigInt `mtimeMs`. This preserves the existing public representation;
it does not claim nanosecond-exact comparison. `modifiedAt` remains an ISO date.

These snapshots establish file identity, not flock ownership. They do not solve
opener attribution, process identity, namespace visibility, or remote filesystem
lock semantics. Linux fdinfo adoption still requires its separate safety gates.
