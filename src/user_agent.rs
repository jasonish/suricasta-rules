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
        match std::env::consts::OS {
            "windows" => "Windows".to_string(),
            "linux" => "Linux".to_string(),
            other => other.to_string(),
        }
    }

    fn get_cpu() -> String {
        std::env::consts::ARCH.to_string()
    }

    fn get_dist() -> String {
        // Windows-specific distribution detection
        if cfg!(target_os = "windows") {
            if let Some(version) = Self::get_windows_version() {
                return format!("Windows/{version}");
            }
            return "Windows".to_string();
        }

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

    fn get_windows_version() -> Option<String> {
        // On Windows, we can use WMI or registry to get version info
        // For simplicity, we'll try to read from environment variables or use a basic approach

        // Try to get Windows version from environment
        if let Ok(output) = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            if let Ok(ver_output) = String::from_utf8(output.stdout) {
                // Parse Windows version from "ver" command output
                // Example: "Microsoft Windows [Version 10.0.22631.4602]"
                if let Some(start) = ver_output.find("Version ") {
                    let version_part = &ver_output[start + 8..];
                    if let Some(end) = version_part.find(']') {
                        let version = version_part[..end].trim();
                        // Extract major version for common Windows versions
                        if version.starts_with("10.0") {
                            return Some("11".to_string()); // Windows 11 is also 10.0.x but with higher build numbers
                        } else if version.starts_with("6.3") {
                            return Some("8.1".to_string());
                        } else if version.starts_with("6.2") {
                            return Some("8".to_string());
                        } else if version.starts_with("6.1") {
                            return Some("7".to_string());
                        } else {
                            // Return the full version if we can't map it
                            return Some(version.to_string());
                        }
                    }
                }
            }
        }

        // Fallback: try using PowerShell to get more detailed Windows version
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem).Caption",
            ])
            .output()
        {
            if let Ok(ps_output) = String::from_utf8(output.stdout) {
                let caption = ps_output.trim();
                if caption.contains("Windows 11") {
                    return Some("11".to_string());
                } else if caption.contains("Windows 10") {
                    return Some("10".to_string());
                } else if caption.contains("Windows 8.1") {
                    return Some("8.1".to_string());
                } else if caption.contains("Windows 8") {
                    return Some("8".to_string());
                } else if caption.contains("Windows 7") {
                    return Some("7".to_string());
                } else if caption.contains("Server") {
                    // Extract server version if possible
                    if caption.contains("2022") {
                        return Some("Server 2022".to_string());
                    } else if caption.contains("2019") {
                        return Some("Server 2019".to_string());
                    } else if caption.contains("2016") {
                        return Some("Server 2016".to_string());
                    } else {
                        return Some("Server".to_string());
                    }
                }
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
