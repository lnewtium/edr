use rusqlite::{params, Connection};
use crate::util::elf_path_from_pid;

pub struct ProgramIdentity {
    pub id: u32,
}
pub fn resolve_identity(conn: &Connection, pid: u32) -> Option<ProgramIdentity> {
    let parent = match elf_path_from_pid(pid) {
        Ok(p) => match p.to_str() {
            Some(p2) => p2.to_string(),
            None => return None,
        },
        Err(_) => return None,
    };

    let identity = conn.query_row(
        "SELECT id FROM programs WHERE parent=?",
        params![parent.clone()],
        |identity| {
            Ok(ProgramIdentity {
                id: identity.get(0)?,
            })
        }
    );

    match identity {
        Ok(i) => Some(i),
        Err(_) => {
            conn.execute("INSERT INTO programs(parent) VALUES (?1)", params![parent.clone()]).unwrap();
            Some(conn.query_row(
                "SELECT id FROM programs WHERE parent=?",
                params![parent.clone()],
                |identity| {
                    Ok(ProgramIdentity {
                        id: identity.get(0)?,
                    })
                }
            ).unwrap())
        },
    }
}
