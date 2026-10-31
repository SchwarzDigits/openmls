# SchwarzDigits fork: openmls_sqlite_storage over the SchwarzDigits rusqlite

This branch (`sqlite3mc/sqlite_storage-0.3`) is the `openmls_sqlite_storage`
0.3.0 release with one change in its manifest: `rusqlite` and `refinery` come
from the SchwarzDigits forks that bundle SQLite3 Multiple Ciphers
([SchwarzDigits/rusqlite](https://github.com/SchwarzDigits/rusqlite),
[SchwarzDigits/refinery](https://github.com/SchwarzDigits/refinery)), by tag,
and `openmls_traits` from crates.io instead of the workspace path, so a
consumer on the crates.io openmls 0.9 line holds the trait crate once. The
code is upstream's. The branch is rebased on the openmls release tag that
publishes the sqlite_storage line in use, and consumed as a git dependency
by its tag. The fork's `main` tracks upstream; the other branches are
upstream pull requests in flight.

---

# OpenMLS SQLite Storage

A codec-independent storage provider implementing the `StorageProvider` trait from `openmls_traits` based on the `rusqlite` crate.
