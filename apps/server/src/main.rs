//! # OpenAudit Server
//!
//! Control plane binary for OpenAudit, serving the REST API and executing
//! scheduled scan tasks via PostgreSQL-backed job orchestration.

fn main() {
    println!("OpenAudit Server v{}", openaudit_core::version());
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_server_entry_point() {
        assert!(!openaudit_core::version().is_empty());
    }
}
