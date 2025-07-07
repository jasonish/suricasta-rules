// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use std::fmt;
use std::fs;

pub struct UserAgent {
    version: String,
    os: String,
    cpu: String,
    dist: String,
}

impl UserAgent {
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: Self::get_os(),
            cpu: Self::get_cpu(),
            dist: Self::get_dist(),
        }
    }

    fn get_os() -> String {
        std::env::consts::OS.to_string()
    }

    fn get_cpu() -> String {
        std::env::consts::ARCH.to_string()
    }

    fn get_dist() -> String {
        // Try to read distribution info from /etc/os-release
        if let Ok(content) = fs::read_to_string("/etc/os-release") {
            if let Some(name) = Self::extract_os_release_field(&content, "NAME") {
                if let Some(version) = Self::extract_os_release_field(&content, "VERSION_ID") {
                    return format!("{name}/{version}");
                } else if let Some(version) = Self::extract_os_release_field(&content, "BUILD_ID") {
                    return format!("{name}/{version}");
                } else {
                    return name;
                }
            }
        }

        // Fallback: try other common files
        if let Ok(content) = fs::read_to_string("/etc/redhat-release") {
            return content.trim().to_string();
        }

        if let Ok(content) = fs::read_to_string("/etc/debian_version") {
            return format!("Debian/{}", content.trim());
        }

        // If we can't determine the distribution, return empty string
        String::new()
    }

    fn extract_os_release_field(content: &str, field: &str) -> Option<String> {
        for line in content.lines() {
            if line.starts_with(&format!("{field}=")) {
                let value = line.split('=').nth(1)?;
                // Remove quotes if present
                let value = value.trim_matches('"').trim_matches('\'');
                return Some(value.to_string());
            }
        }
        None
    }
}

impl Default for UserAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Suricasta-Rules/{} (OS: {}; CPU: {}; Dist: {})",
            self.version, self.os, self.cpu, self.dist
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_agent_format() {
        let ua = UserAgent::new();
        let ua_string = ua.to_string();
        assert!(ua_string.starts_with("Suricasta-Rules/"));
        assert!(ua_string.contains("OS:"));
        assert!(ua_string.contains("CPU:"));
        assert!(ua_string.contains("Dist:"));
    }

    #[test]
    fn test_extract_os_release_field() {
        let content = r#"NAME="Ubuntu"
VERSION_ID="20.04"
ID=ubuntu"#;

        assert_eq!(
            UserAgent::extract_os_release_field(content, "NAME"),
            Some("Ubuntu".to_string())
        );
        assert_eq!(
            UserAgent::extract_os_release_field(content, "VERSION_ID"),
            Some("20.04".to_string())
        );
        assert_eq!(
            UserAgent::extract_os_release_field(content, "ID"),
            Some("ubuntu".to_string())
        );
        assert_eq!(
            UserAgent::extract_os_release_field(content, "NONEXISTENT"),
            None
        );
    }
}
