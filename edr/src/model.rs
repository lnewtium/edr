use std::path::PathBuf;
use rusqlite::{Connection, OpenFlags};

pub fn open_db(db: PathBuf) -> Connection {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    ).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS programs (
            id INTEGER PRIMARY KEY,
            parent TEXT,
            UNIQUE(parent)
        );
        CREATE TABLE IF NOT EXISTS behaviors (
            parent_id INTEGER,
            filename TEXT,
            syscall TEXT,
            argv_hash TEXT,
            count INTEGER,
            UNIQUE(parent_id, syscall, filename, argv_hash)
        );",
    ).unwrap();
    conn
}