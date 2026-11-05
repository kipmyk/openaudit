//! # OpenAudit Agent
//!
//! Lightweight, outbound-only background daemon for monitored Linux nodes.
//! Operates with zero listening ports and executes read-only posture checks.

fn main() {
    println!("OpenAudit Agent v{}", openaudit_core::version());
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_agent_entry_point() {
        assert_ne!(openaudit_core::version(), "");
    }
}
