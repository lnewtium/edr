use rusqlite::{params, Connection};
use crate::identity::ProgramIdentity;
use sha2::{Digest, Sha256};

// fn looks_like_hex(s: &str) -> bool {
//    s.len() > 8 && s.chars().all(|c| c.is_ascii_hexdigit())
//}

pub fn compute_argv_hash(argv: &Vec::<String>) -> String {
    // TODO: Normalization
    // for i in 0..argv.len() {
    //     if argv[i].starts_with("/home/") {
    //         "/home/*".into()
    //     } else if argv[i].starts_with("/tmp/") {
    //         "/tmp/*".into()
    //     } else if argv[i].parse::<u64>().is_ok() {
    //         "<NUM>".into()
    //     } else if argv[i].len() > 64 {
    //         "<LONG>".into()
    //     } else {
    //         arg.into()
    //     }
    // }
    let combined = argv.join(",");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();

    hex::encode(result)
}

pub fn insert_program(conn: &Connection, prog: ProgramIdentity, syscall: &str, filename: &str, argv: &Vec::<String>) -> rusqlite::Result<usize> {
    let argv_hash = compute_argv_hash(argv);
    conn.execute(
        "INSERT INTO behaviors(parent_id, syscall, filename, argv_hash, count)
         VALUES (?, ?, ?, ?, 1)
         ON CONFLICT(parent_id, syscall, filename, argv_hash)
         DO UPDATE SET count = count + 1",
        params![prog.id, syscall, filename, argv_hash],
    )
}

pub fn select_program_count(conn: &Connection, prog: ProgramIdentity, syscall: &str, filename: &str, argv: &Vec::<String>) -> rusqlite::Result<u32> {
    let argv_hash = compute_argv_hash(argv);
    let mut stmt = conn.prepare(
        "SELECT count FROM behaviors
         WHERE parent_id = ? AND syscall = ? AND filename = ? AND argv_hash = ?",
    )?;
    let count: u32 = stmt.query_row(
        params![prog.id, syscall, filename, argv_hash],
        |row| row.get(0),
    ).unwrap_or(0);
    Ok(count)
}