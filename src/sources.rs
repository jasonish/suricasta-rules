// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use crate::paths::PathProvider;
use crate::user_agent::UserAgent;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::debug;

const DEFAULT_INDEX_URL: &str = "https://www.openinfosecfoundation.org/rules/index.yaml";
const INDEX_FILENAME: &str = "index.yaml";
const CACHE_MIN_AGE_SECS: i64 = 900; // 15 minutes

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SourceInfo {
    pub vendor: String,
    pub summary: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "min-version")]
    pub min_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_yaml::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obsolete: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SourceIndex {
    pub version: u32,
    pub sources: HashMap<String, SourceInfo>,
}

pub struct SourceManager<'a> {
    path_provider: &'a dyn PathProvider,
}

impl<'a> SourceManager<'a> {
    pub fn new(path_provider: &'a dyn PathProvider) -> Self {
        Self { path_provider }
    }

    pub fn get_index_path(&self) -> PathBuf {
        self.path_provider.cache_dir().join(INDEX_FILENAME)
    }

    pub fn get_source_index_url(&self) -> String {
        std::env::var("SOURCE_INDEX_URL").unwrap_or_else(|_| DEFAULT_INDEX_URL.to_string())
    }

    pub fn read_local_index(&self) -> Result<Option<SourceIndex>> {
        let index_path = self.get_index_path();
        if !index_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&index_path).with_context(|| {
            format!(
                "Failed to read index from {}: permission denied",
                index_path.display()
            )
        })?;
        let index: SourceIndex = serde_yaml::from_str(&content)?;
        Ok(Some(index))
    }

    pub fn get_index(&self) -> Result<Option<SourceIndex>> {
        self.read_local_index()
    }

    pub fn get_or_download_index(&self) -> Result<SourceIndex> {
        match self.get_index()? {
            Some(index) => Ok(index),
            None => {
                println!("No sources index found, downloading...");
                self.update_sources()?;
                self.get_index()?.ok_or_else(|| {
                    anyhow::anyhow!("Failed to retrieve index after updating sources")
                })
            }
        }
    }

    pub fn download_index(&self) -> Result<SourceIndex> {
        let url = self.get_source_index_url();
        println!("Downloading {}", url.cyan());

        let user_agent = UserAgent::new().to_string();
        debug!("Using User-Agent: {}", user_agent);
        let client = reqwest::blocking::Client::builder()
            .user_agent(user_agent)
            .build()?;
        let response = client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to download from {url}"))?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download index: HTTP {}",
                response.status()
            ));
        }

        let content = response.text()?;
        let index: SourceIndex = serde_yaml::from_str(&content)?;
        Ok(index)
    }

    pub fn save_index(&self, index: &SourceIndex) -> Result<()> {
        let index_path = self.get_index_path();

        // Ensure cache directory exists
        if let Some(parent) = index_path.parent() {
            crate::paths::ensure_dir_exists(parent).with_context(|| {
                format!(
                    "Failed to create cache directory {}: permission denied",
                    parent.display()
                )
            })?;
        }

        let yaml = serde_yaml::to_string(index)?;
        fs::write(&index_path, yaml).with_context(|| {
            format!(
                "Failed to write index to {}: permission denied",
                index_path.display()
            )
        })?;

        println!("Saved {}", index_path.display());
        Ok(())
    }

    pub fn compare_sources(&self, old: Option<&SourceIndex>, new: &SourceIndex) {
        match old {
            None => {
                println!("{}", "Adding all sources".green());
            }
            Some(old_index) => {
                if old_index.sources == new.sources {
                    println!("{}", "No change in sources".yellow());
                    return;
                }

                // Find added sources
                for name in new.sources.keys() {
                    if !old_index.sources.contains_key(name) {
                        println!("Source {} was {}", name.cyan(), "added".green());
                    }
                }

                // Find removed sources
                for name in old_index.sources.keys() {
                    if !new.sources.contains_key(name) {
                        println!("Source {} was {}", name.cyan(), "removed".red());
                    }
                }

                // Find changed sources
                for (name, new_source) in &new.sources {
                    if let Some(old_source) = old_index.sources.get(name) {
                        if !sources_equal(old_source, new_source) {
                            println!("Source {} was {}", name.cyan(), "changed".yellow());
                        }
                    }
                }
            }
        }
    }

    pub fn update_sources(&self) -> Result<()> {
        // Read existing index if any
        let initial_index = self.read_local_index()?;

        // Download new index
        let new_index = self.download_index()?;

        // Save the new index
        self.save_index(&new_index)?;

        // Compare and report changes
        self.compare_sources(initial_index.as_ref(), &new_index);

        Ok(())
    }

    pub fn update_sources_cached(&self, force: bool, quiet: bool) -> Result<()> {
        let index_path = self.get_index_path();

        // Check if we have a recent cache (unless force is specified)
        if !force && index_path.exists() {
            if let Ok(metadata) = fs::metadata(&index_path) {
                if let Ok(modified) = metadata.modified() {
                    let age = Utc::now()
                        .signed_duration_since(DateTime::<Utc>::from(modified))
                        .num_seconds();
                    if age < CACHE_MIN_AGE_SECS {
                        if !quiet {
                            println!(
                                "  Using cached sources index (age: {} seconds)",
                                age.to_string().bright_black()
                            );
                        }
                        return Ok(());
                    }
                }
            }
        }

        // Read existing index if any
        let initial_index = self.read_local_index()?;

        // Download new index
        let new_index = if quiet {
            // Suppress download message in quiet mode
            let url = self.get_source_index_url();
            let user_agent = UserAgent::new().to_string();
            debug!("Using User-Agent: {}", user_agent);
            let client = reqwest::blocking::Client::builder()
                .user_agent(user_agent)
                .build()?;
            let response = client
                .get(&url)
                .send()
                .with_context(|| format!("Failed to download from {url}"))?;
            if !response.status().is_success() {
                return Err(anyhow::anyhow!(
                    "Failed to download index: HTTP {}",
                    response.status()
                ));
            }
            let content = response.text()?;
            serde_yaml::from_str(&content)?
        } else {
            self.download_index()?
        };

        // Save the new index
        if quiet {
            let index_path = self.get_index_path();
            if let Some(parent) = index_path.parent() {
                crate::paths::ensure_dir_exists(parent).with_context(|| {
                    format!(
                        "Failed to create cache directory {}: permission denied",
                        parent.display()
                    )
                })?;
            }
            let yaml = serde_yaml::to_string(&new_index)?;
            fs::write(&index_path, yaml).with_context(|| {
                format!(
                    "Failed to write index to {}: permission denied",
                    index_path.display()
                )
            })?;
        } else {
            self.save_index(&new_index)?;
        }

        // Compare and report changes (only if not quiet)
        if !quiet {
            self.compare_sources(initial_index.as_ref(), &new_index);
        }

        Ok(())
    }
}

fn sources_equal(a: &SourceInfo, b: &SourceInfo) -> bool {
    // Compare all fields that matter for detecting changes
    a.vendor == b.vendor
        && a.summary == b.summary
        && a.url == b.url
        && a.description == b.description
        && a.license == b.license
        && a.homepage == b.homepage
        && a.min_version == b.min_version
        && a.checksum == b.checksum
        && a.parameters == b.parameters
        && a.replaces == b.replaces
        && a.deprecated == b.deprecated
        && a.obsolete == b.obsolete
}
