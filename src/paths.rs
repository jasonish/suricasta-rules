// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use directories::BaseDirs;
use std::path::{Path, PathBuf};

pub trait PathProvider {
    fn sources_dir(&self) -> PathBuf;
    fn cache_dir(&self) -> PathBuf;
    fn rules_dir(&self) -> PathBuf;
}

pub struct UnixSystemPaths;

impl PathProvider for UnixSystemPaths {
    fn sources_dir(&self) -> PathBuf {
        PathBuf::from("/var/lib/suricata/update/sources")
    }

    fn cache_dir(&self) -> PathBuf {
        PathBuf::from("/var/lib/suricata/update/cache")
    }

    fn rules_dir(&self) -> PathBuf {
        PathBuf::from("/var/lib/suricata/rules")
    }
}

pub struct UserPaths {
    base_dirs: BaseDirs,
}

impl UserPaths {
    pub fn new() -> Option<Self> {
        BaseDirs::new().map(|base_dirs| Self { base_dirs })
    }
}

impl PathProvider for UserPaths {
    fn sources_dir(&self) -> PathBuf {
        // Use ~/.local/share/suricata/update/sources to match suricata-update
        self.base_dirs
            .data_local_dir()
            .join("suricata")
            .join("update")
            .join("sources")
    }

    fn cache_dir(&self) -> PathBuf {
        // Use ~/.cache/suricata/update to match suricata-update
        self.base_dirs.cache_dir().join("suricata").join("update")
    }

    fn rules_dir(&self) -> PathBuf {
        // Use ~/.local/share/suricata/rules to match suricata-update
        self.base_dirs
            .data_local_dir()
            .join("suricata")
            .join("rules")
    }
}

pub fn get_path_provider(user_mode: bool) -> Box<dyn PathProvider> {
    if user_mode {
        match UserPaths::new() {
            Some(paths) => Box::new(paths),
            None => {
                eprintln!(
                    "Warning: Could not determine user directories, falling back to system paths"
                );
                Box::new(UnixSystemPaths)
            }
        }
    } else {
        Box::new(UnixSystemPaths)
    }
}

pub fn ensure_dir_exists(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!("Permission denied creating directory {}", path.display())
            } else {
                anyhow::anyhow!("Failed to create directory {}: {}", path.display(), e)
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_paths() {
        let paths = UnixSystemPaths;
        assert_eq!(
            paths.sources_dir(),
            PathBuf::from("/var/lib/suricata/update/sources")
        );
        assert_eq!(
            paths.cache_dir(),
            PathBuf::from("/var/lib/suricata/update/cache")
        );
        assert_eq!(paths.rules_dir(), PathBuf::from("/var/lib/suricata/rules"));
    }

    #[test]
    fn test_user_paths_creation() {
        // This test might fail on systems without a home directory
        if let Some(paths) = UserPaths::new() {
            let sources = paths.sources_dir();
            let cache = paths.cache_dir();
            let rules = paths.rules_dir();

            // Just verify they return paths
            assert!(!sources.as_os_str().is_empty());
            assert!(!cache.as_os_str().is_empty());
            assert!(!rules.as_os_str().is_empty());

            // Verify they end with expected components
            assert!(sources.ends_with("sources"));
            assert!(rules.ends_with("rules"));
        }
    }
}
