# SchwarzDigits fork: openmls_sqlite_storage over the SchwarzDigits rusqlite

This branch (`schwarzdigits/openmls-0.9`) carries the SchwarzDigits changes
on the openmls 0.9 release line. For this crate it is the
`openmls_sqlite_storage` 0.3.0 release with two changes. In its manifest,
`rusqlite` and `refinery` come from the SchwarzDigits forks that bundle
SQLite3 Multiple Ciphers
([SchwarzDigits/rusqlite](https://github.com/SchwarzDigits/rusqlite),
[SchwarzDigits/refinery](https://github.com/SchwarzDigits/refinery)), by tag,
and `openmls_traits` from crates.io instead of the workspace path, so a
consumer on the crates.io openmls 0.9 line holds the trait crate once. In its
code, `run_migrations` applies all pending migrations in one transaction
(refinery's `set_grouped`), so a crash during the run cannot leave a
migration applied but unrecorded: a backport of
[openmls/openmls#2323](https://github.com/openmls/openmls/pull/2323) with its
regression tests. Otherwise the code is upstream's. The branch is rebased on
the openmls release tag that publishes the sqlite_storage line in use, and
consumed as a git dependency by its tag. The fork's `main` tracks upstream;
the other branches are upstream pull requests in flight. (First published as
`sqlite3mc/sqlite_storage-0.3`, tag `sqlite_storage-v0.3.0-sqlite3mc`,
which stays for the consumers that pin it.)

---

# OpenMLS SQLite Storage

A codec-independent storage provider implementing the `StorageProvider` trait from `openmls_traits` based on the `rusqlite` crate.
