// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use crate::paths::PathProvider;
use crate::rulesets::RulesetManager;
use crate::sources::{SourceInfo, SourceManager};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use tar::Archive;
use zip::ZipArchive;

const DEFAULT_OUTPUT_FILE: &str = "suricata.rules";
const CACHE_MIN_AGE_SECS: i64 = 900; // 15 minutes

pub struct UpdateManager<'a> {
    path_provider: &'a dyn PathProvider,
    suricata_version: String,
}

#[derive(Debug)]
struct SourceFile {
    filename: String,
    content: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Rule {
    raw: String,
    enabled: bool,
    sid: u32,
    gid: u32,
    rev: u32,
    #[allow(dead_code)]
    msg: String,
}

impl<'a> UpdateManager<'a> {
    pub fn new(path_provider: &'a dyn PathProvider) -> Self {
        Self {
            path_provider,
            suricata_version: Self::get_suricata_version(),
        }
    }

    fn get_suricata_version() -> String {
        // TODO: Get actual suricata version by running suricata -V
        // For now, default to 7.0.0
        "7.0.0".to_string()
    }

    pub fn update(&self, force: bool, quiet: bool) -> Result<()> {
        // Macro for conditional printing (only print if not quiet)
        macro_rules! info_println {
            ($($arg:tt)*) => {
                if !quiet {
                    println!($($arg)*);
                }
            };
        }

        info_println!("{}", "Running Suricata rule update...".green().bold());

        // First, update sources
        let source_manager = SourceManager::new(self.path_provider);
        info_println!("\n{}", "Updating sources...".cyan());
        source_manager.update_sources_cached(force, quiet)?;

        // Get enabled sources
        let ruleset_manager = RulesetManager::new(self.path_provider);
        let mut enabled_sources = ruleset_manager.get_enabled_sources()?;

        // If no sources are enabled, use et/open as a fallback without enabling it
        if enabled_sources.is_empty() {
            println!(
                "{}: No sources configured, will use Emerging Threats Open as fallback",
                "Info".yellow()
            );
            enabled_sources = vec!["et/open".to_string()];
        }

        // Load source index (it should be fresh after update)
        let source_index = source_manager.get_index()?.ok_or_else(|| {
            anyhow::anyhow!(
                "No sources index found after updating sources. The index download may have failed."
            )
        })?;

        // Download and process each enabled source
        let mut all_rules: HashMap<String, Rule> = HashMap::new();
        for source_name in &enabled_sources {
            info_println!("\nProcessing source: {}", source_name.cyan());

            if let Some(source_info) = source_index.sources.get(source_name) {
                match self.process_source(source_name, source_info, force, quiet) {
                    Ok(rules) => {
                        info_println!(
                            "  Loaded {} rules from {}",
                            rules.len().to_string().green(),
                            source_name.cyan()
                        );
                        // Merge rules, preferring higher revision numbers
                        for (key, rule) in rules {
                            match all_rules.get(&key) {
                                Some(existing) if existing.rev >= rule.rev => {}
                                _ => {
                                    all_rules.insert(key, rule);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{}: Failed to process {}: {}",
                            "Error".red(),
                            source_name,
                            e
                        );
                    }
                }
            } else {
                eprintln!(
                    "{}: Source {} not found in index",
                    "Warning".yellow(),
                    source_name
                );
            }
        }

        // Write merged rules to output file
        self.write_rules(&all_rules)?;

        info_println!(
            "\n{}: Wrote {} rules to {}",
            "Success".green().bold(),
            all_rules.len().to_string().green(),
            self.get_output_path().display()
        );

        Ok(())
    }

    fn is_tty() -> bool {
        // Check if stdout is a TTY
        std::io::stdout().is_terminal()
    }

    fn process_source(
        &self,
        source_name: &str,
        source_info: &SourceInfo,
        force: bool,
        quiet: bool,
    ) -> Result<HashMap<String, Rule>> {
        // Download the source
        let archive_path = self.download_source(source_name, source_info, force, quiet)?;

        // Extract rules from archive
        let source_files = self.extract_archive(&archive_path)?;

        // Parse rules from extracted files
        let mut rules = HashMap::new();
        for file in source_files {
            if std::path::Path::new(&file.filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rules"))
            {
                let file_rules = self.parse_rules(&file.content)?;
                for rule in file_rules {
                    let key = format!("{}:{}", rule.gid, rule.sid);
                    rules.insert(key, rule);
                }
            }
        }

        Ok(rules)
    }

    fn download_source(
        &self,
        source_name: &str,
        source_info: &SourceInfo,
        force: bool,
        quiet: bool,
    ) -> Result<PathBuf> {
        // Resolve URL template
        let url = self.resolve_url(&source_info.url);

        // Generate cache filename based on URL hash
        let url_hash = format!("{:x}", md5::compute(url.as_bytes()));
        let cache_filename = format!("{}.tar.gz", url_hash);
        let cache_path = self.path_provider.cache_dir().join(&cache_filename);

        // Check if we have a recent cache (unless force is specified)
        if !force && cache_path.exists() {
            if let Ok(metadata) = fs::metadata(&cache_path) {
                if let Ok(modified) = metadata.modified() {
                    let age = Utc::now()
                        .signed_duration_since(DateTime::<Utc>::from(modified))
                        .num_seconds();
                    if age < CACHE_MIN_AGE_SECS {
                        if !quiet {
                            println!(
                                "  Using cached file (age: {} seconds)",
                                age.to_string().bright_black()
                            );
                        }
                        return Ok(cache_path);
                    }
                }
            }
        }

        // Ensure cache directory exists
        crate::paths::ensure_dir_exists(&self.path_provider.cache_dir()).with_context(|| {
            format!(
                "Failed to create cache directory {}: permission denied",
                self.path_provider.cache_dir().display()
            )
        })?;

        // Download the file
        if force && cache_path.exists() && !quiet {
            println!("  Forcing download (ignoring cache)");
        }
        if !quiet {
            println!("  Downloading: {}", url.bright_black());
        }

        let mut response =
            reqwest::blocking::get(&url).with_context(|| format!("Failed to download {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download {}: HTTP {}",
                source_name,
                response.status()
            ));
        }

        // Get content length for progress bar
        let content_length = response.content_length();

        // Create progress bar if we have a TTY and know the content length (and not quiet)
        let progress_bar = if Self::is_tty() && content_length.is_some() && !quiet {
            let progress_bar = ProgressBar::new(content_length.unwrap());
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                    .unwrap()
                    .progress_chars("#>-")
            );
            Some(progress_bar)
        } else {
            None
        };

        // Download with progress
        let mut downloaded = Vec::new();
        let mut buffer = [0; 8192];

        loop {
            let bytes_read = response.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            downloaded.extend_from_slice(&buffer[..bytes_read]);

            if let Some(ref pb) = progress_bar {
                pb.inc(bytes_read as u64);
            }
        }

        if let Some(pb) = progress_bar {
            pb.finish_and_clear();
        }

        // Write to cache file
        let mut file = fs::File::create(&cache_path).with_context(|| {
            format!(
                "Failed to create cache file {}: permission denied",
                cache_path.display()
            )
        })?;
        file.write_all(&downloaded).with_context(|| {
            format!(
                "Failed to write to cache file {}: permission denied",
                cache_path.display()
            )
        })?;

        if !quiet {
            println!(
                "  Downloaded {} bytes",
                downloaded.len().to_string().green()
            );
        }
        Ok(cache_path)
    }

    fn resolve_url(&self, url_template: &str) -> String {
        // Replace %(__version__)s with suricata version
        url_template.replace("%(__version__)s", &self.suricata_version)
    }

    fn extract_archive(&self, archive_path: &Path) -> Result<Vec<SourceFile>> {
        let mut files = Vec::new();
        let file = fs::File::open(archive_path)?;

        if archive_path.to_string_lossy().ends_with(".tar.gz") {
            // Handle tar.gz files
            let tar = GzDecoder::new(file);
            let mut archive = Archive::new(tar);

            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?;

                // Skip directories
                if entry.header().entry_type().is_dir() {
                    continue;
                }

                let filename = path.to_string_lossy().to_string();
                let mut content = Vec::new();
                entry.read_to_end(&mut content)?;

                files.push(SourceFile { filename, content });
            }
        } else if archive_path.to_string_lossy().ends_with(".zip") {
            // Handle zip files
            let mut archive = ZipArchive::new(file)?;

            for i in 0..archive.len() {
                let mut file = archive.by_index(i)?;

                // Skip directories
                if file.is_dir() {
                    continue;
                }

                let filename = file.name().to_string();
                let mut content = Vec::new();
                file.read_to_end(&mut content)?;

                files.push(SourceFile { filename, content });
            }
        } else {
            return Err(anyhow::anyhow!("Unsupported archive format"));
        }

        Ok(files)
    }

    fn parse_rules(&self, content: &[u8]) -> Result<Vec<Rule>> {
        let content_str = String::from_utf8_lossy(content);
        let mut rules = Vec::new();

        // Simple rule parser - matches basic rule structure
        let rule_regex = Regex::new(r"^(#?\s*)?(alert|drop|pass|reject)\s+.*?sid:\s*(\d+).*?;")?;
        let sid_regex = Regex::new(r"sid:\s*(\d+)")?;
        let gid_regex = Regex::new(r"gid:\s*(\d+)")?;
        let rev_regex = Regex::new(r"rev:\s*(\d+)")?;
        let msg_regex = Regex::new(r#"msg:\s*"([^"]+)""#)?;

        for line in content_str.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') && !trimmed.contains("sid:") {
                continue;
            }

            if rule_regex.is_match(trimmed) {
                let enabled = !trimmed.starts_with('#');
                let raw = trimmed.to_string();

                // Extract rule components
                let sid = sid_regex
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u32>().ok())
                    .unwrap_or(0);

                let gid = gid_regex
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u32>().ok())
                    .unwrap_or(1);

                let rev = rev_regex
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<u32>().ok())
                    .unwrap_or(1);

                let msg = msg_regex
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                if sid > 0 {
                    rules.push(Rule {
                        raw,
                        enabled,
                        sid,
                        gid,
                        rev,
                        msg,
                    });
                }
            }
        }

        Ok(rules)
    }

    fn write_rules(&self, rules: &HashMap<String, Rule>) -> Result<()> {
        let output_path = self.get_output_path();

        // Ensure output directory exists
        if let Some(parent) = output_path.parent() {
            crate::paths::ensure_dir_exists(parent).with_context(|| {
                format!(
                    "Failed to create output directory {}: permission denied",
                    parent.display()
                )
            })?;
        }

        // Sort rules by gid:sid for consistent output
        let mut sorted_rules: Vec<_> = rules.values().collect();
        sorted_rules.sort_by_key(|r| (r.gid, r.sid));

        // Write rules to file
        let mut file = fs::File::create(&output_path).with_context(|| {
            format!(
                "Failed to create output file {}: permission denied",
                output_path.display()
            )
        })?;
        for rule in sorted_rules {
            if rule.enabled {
                writeln!(file, "{}", rule.raw)?;
            }
        }

        Ok(())
    }

    fn get_output_path(&self) -> PathBuf {
        self.path_provider.rules_dir().join(DEFAULT_OUTPUT_FILE)
    }
}
