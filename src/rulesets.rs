// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use crate::paths::PathProvider;
use crate::sources::{SourceIndex, SourceInfo};
use anyhow::{Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct EnabledSource {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HashMap<String, serde_yaml::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "http-header")]
    pub http_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<bool>,
}

impl EnabledSource {
    pub fn new(source_name: String) -> Self {
        Self {
            source: source_name,
            url: None,
            params: None,
            http_header: None,
            checksum: None,
        }
    }
}

pub struct RulesetManager<'a> {
    path_provider: &'a dyn PathProvider,
}

impl<'a> RulesetManager<'a> {
    pub fn new(path_provider: &'a dyn PathProvider) -> Self {
        Self { path_provider }
    }

    fn safe_filename(name: &str) -> String {
        name.replace('/', "-")
    }

    fn get_source_file_path(&self, name: &str) -> PathBuf {
        let filename = format!("{}.yaml", Self::safe_filename(name));
        self.path_provider.sources_dir().join(filename)
    }

    fn get_disabled_file_path(&self, name: &str) -> PathBuf {
        let filename = format!("{}.yaml.disabled", Self::safe_filename(name));
        self.path_provider.sources_dir().join(filename)
    }

    pub fn is_source_enabled(&self, name: &str) -> bool {
        self.get_source_file_path(name).exists()
    }

    pub fn get_enabled_sources(&self) -> Result<Vec<String>> {
        let sources_dir = self.path_provider.sources_dir();
        let mut enabled = Vec::new();

        if sources_dir.exists() {
            for entry in fs::read_dir(&sources_dir).with_context(|| {
                format!(
                    "Failed to read sources directory {}: permission denied",
                    sources_dir.display()
                )
            })? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if !std::path::Path::new(stem)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml"))
                        {
                            let content = fs::read_to_string(&path).with_context(|| {
                                format!("Failed to read {}: permission denied", path.display())
                            })?;
                            let source: EnabledSource = serde_yaml::from_str(&content)
                                .with_context(|| format!("Failed to parse {}", path.display()))?;
                            enabled.push(source.source);
                        }
                    }
                }
            }
        }

        Ok(enabled)
    }

    pub fn enable_source(&self, name: &str, source_info: Option<&SourceInfo>) -> Result<()> {
        // Check if the ruleset is obsolete
        if let Some(info) = source_info {
            if let Some(obsolete_msg) = &info.obsolete {
                return Err(anyhow::anyhow!(
                    "Cannot enable obsolete ruleset '{}': {}",
                    name,
                    obsolete_msg
                ));
            }
        }

        let sources_dir = self.path_provider.sources_dir();
        crate::paths::ensure_dir_exists(&sources_dir)?;

        let source_file = self.get_source_file_path(name);
        let disabled_file = self.get_disabled_file_path(name);

        if source_file.exists() {
            println!(
                "{}: Ruleset {} is already enabled",
                "Info".yellow(),
                name.cyan()
            );
            return Ok(());
        }

        if disabled_file.exists() {
            fs::rename(&disabled_file, &source_file).with_context(|| {
                format!(
                    "Failed to re-enable source {}: permission denied for file {}",
                    name,
                    disabled_file.display()
                )
            })?;
            println!("Re-enabled previously disabled ruleset: {}", name.cyan());
        } else {
            let enabled_source = EnabledSource::new(name.to_string());
            let yaml = serde_yaml::to_string(&enabled_source)?;
            fs::write(&source_file, yaml).with_context(|| {
                format!(
                    "Failed to write source file {}: permission denied",
                    source_file.display()
                )
            })?;
            println!("Enabled ruleset: {}", name.cyan());
        }

        if let Some(info) = source_info {
            if let Some(vendor) = info.vendor.as_str().split('/').next() {
                println!("  Vendor: {}", vendor.bright_black());
            }
            println!("  Summary: {}", info.summary.bright_black());
        }

        let enabled_count = self.get_enabled_sources()?.len();
        if enabled_count == 1 && name != "et/open" {
            self.enable_default_source()?;
        }

        Ok(())
    }

    fn enable_default_source(&self) -> Result<()> {
        let default_source = "et/open";
        if !self.is_source_enabled(default_source) {
            println!("\nEnabling default ruleset: {}", default_source.cyan());
            let enabled_source = EnabledSource::new(default_source.to_string());
            let yaml = serde_yaml::to_string(&enabled_source)?;
            let source_file = self.get_source_file_path(default_source);
            fs::write(&source_file, yaml).with_context(|| {
                format!(
                    "Failed to write default source file {}: permission denied",
                    source_file.display()
                )
            })?;
        }
        Ok(())
    }

    pub fn disable_source(&self, name: &str) -> Result<()> {
        let source_file = self.get_source_file_path(name);
        let disabled_file = self.get_disabled_file_path(name);

        if !source_file.exists() {
            println!(
                "{}: Ruleset {} is not enabled",
                "Info".yellow(),
                name.cyan()
            );
            return Ok(());
        }

        // Move the source file to disabled
        fs::rename(&source_file, &disabled_file).with_context(|| {
            format!(
                "Failed to disable source {}: permission denied for file {}",
                name,
                source_file.display()
            )
        })?;

        println!("Disabled ruleset: {}", name.cyan());
        Ok(())
    }

    pub fn select_source(&self, source_index: &SourceIndex) -> Result<Option<String>> {
        let mut available_sources: Vec<(&String, &SourceInfo)> = source_index
            .sources
            .iter()
            .filter(|(_, info)| {
                info.parameters.is_none() && info.obsolete.is_none() && info.deprecated.is_none()
            })
            .collect();

        available_sources.sort_by_key(|(name, _)| name.as_str());

        if available_sources.is_empty() {
            println!(
                "{}: No sources available without parameters",
                "Warning".yellow()
            );
            return Ok(None);
        }

        let options: Vec<String> = available_sources
            .iter()
            .map(|(name, info)| format!("{} - {}", name, info.summary))
            .collect();

        let selection = inquire::Select::new("Select a ruleset to enable:", options)
            .with_page_size(15)
            .prompt()?;

        let selected_index = available_sources
            .iter()
            .position(|(name, info)| format!("{} - {}", name, info.summary) == selection)
            .unwrap();

        Ok(Some(available_sources[selected_index].0.clone()))
    }

    pub fn select_enabled_source(&self) -> Result<Option<String>> {
        let enabled_sources = self.get_enabled_sources()?;

        if enabled_sources.is_empty() {
            println!("{}: No rulesets are currently enabled", "Info".yellow());
            return Ok(None);
        }

        let mut sorted_sources = enabled_sources;
        sorted_sources.sort();

        let selection =
            inquire::Select::new("Select a ruleset to disable:", sorted_sources.clone())
                .with_page_size(15)
                .prompt()?;

        Ok(Some(selection))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_filename() {
        assert_eq!(RulesetManager::<'_>::safe_filename("et/open"), "et-open");
        assert_eq!(RulesetManager::<'_>::safe_filename("simple"), "simple");
        assert_eq!(RulesetManager::<'_>::safe_filename("a/b/c"), "a-b-c");
    }
}
