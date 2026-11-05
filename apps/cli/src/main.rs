//! # OpenAudit CLI
//!
//! Command-line interface for OpenAudit, enabling operators to run direct local
//! host posture audits and interact with remote OpenAudit servers.

fn main() {
    println!("OpenAudit CLI v{}", openaudit_core::version());
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cli_entry_point() {
        assert_ne!(openaudit_core::version(), "");
    }
}
