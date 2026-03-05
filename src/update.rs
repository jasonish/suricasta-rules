// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use crate::paths::PathProvider;
use crate::rulesets::RulesetManager;
use crate::sources::{SourceInfo, SourceManager};
use crate::user_agent::UserAgent;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::cmp::Reverse;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use tar::Archive;
use tracing::debug;
use zip::ZipArchive;

const DEFAULT_OUTPUT_FILE: &str = "suricata.rules";
const DATASETS_DIR: &str = "datasets";
const LEGACY_MANAGED_DATASETS_DIR: &str = "suricasta";
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

#[derive(Debug)]
struct ProcessedSource {
    rules: HashMap<String, Rule>,
}

#[derive(Debug, Clone)]
struct ResolvedDataset {
    output_path: PathBuf,
    content: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Rule {
    raw: String,
    enabled: bool,
    sid: u32,
    gid: u32,
    rev: u32,
    group: String,
    datasets: Vec<ResolvedDataset>,
    #[allow(dead_code)]
    msg: String,
}

impl<'a> UpdateManager<'a> {
    pub fn new(path_provider: &'a dyn PathProvider) -> Self {
        Self::new_with_suricata_version(path_provider, None)
    }

    pub fn new_with_suricata_version(
        path_provider: &'a dyn PathProvider,
        suricata_version: Option<&str>,
    ) -> Self {
        let suricata_version = suricata_version
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(Self::get_suricata_version);

        Self {
            path_provider,
            suricata_version,
        }
    }

    fn get_suricata_version() -> String {
        if let Ok(output) = std::process::Command::new("suricata").arg("-V").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Output looks like: "This is Suricata version 7.0.7 RELEASE"
                if let Some(version) = Self::parse_suricata_version(&stdout) {
                    debug!("Detected Suricata version: {}", version);
                    return version;
                }
            }
        }
        debug!("Could not detect Suricata version, using default 7.0.0");
        "7.0.0".to_string()
    }

    fn parse_suricata_version(output: &str) -> Option<String> {
        let re = Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        re.captures(output)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_owned())
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
                    Ok(processed) => {
                        info_println!(
                            "  Loaded {} rules from {}",
                            processed.rules.len().to_string().green(),
                            source_name.cyan()
                        );

                        // Merge rules, preferring higher revision numbers
                        for (key, rule) in processed.rules {
                            Self::insert_rule_prefer_newer(&mut all_rules, key, rule);
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

        let all_dataset_files = Self::collect_dataset_files(&all_rules);

        // Write merged rules and datasets to output files
        self.write_rules(&all_rules)?;
        self.write_dataset_files(&all_dataset_files)?;

        info_println!(
            "\n{}: Wrote {} rules and {} dataset files to {}",
            "Success".green().bold(),
            all_rules.len().to_string().green(),
            all_dataset_files.len().to_string().green(),
            self.path_provider.rules_dir().display()
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
    ) -> Result<ProcessedSource> {
        // Download the source
        let archive_path = self.download_source(source_name, source_info, force, quiet)?;

        // Extract files from archive
        let source_files = self.extract_archive(&archive_path)?;

        // Partition source files into dependency files and rule files.
        let mut dep_files: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        let mut rule_files: Vec<SourceFile> = Vec::new();
        for file in source_files {
            if Self::is_rules_file(&file.filename) {
                rule_files.push(file);
            } else if let Some(path) = Self::normalize_relative_path(Path::new(&file.filename)) {
                dep_files.insert(path, file.content);
            }
        }

        // Parse rules and collect dataset files referenced by those rules.
        let mut rules = HashMap::new();

        for file in rule_files {
            let file_rules = self.parse_rules(&file.filename, &file.content)?;
            for rule in file_rules {
                if let Some((rewritten_rule, rule_datasets)) =
                    Self::resolve_rule_datasets(source_name, &rule, &dep_files)?
                {
                    let mut rule = rule;
                    rule.raw = rewritten_rule;
                    rule.datasets = rule_datasets;
                    let key = format!("{}:{}", rule.gid, rule.sid);
                    Self::insert_rule_prefer_newer(&mut rules, key, rule);
                } else {
                    eprintln!(
                        "{}: Missing dataset file for rule {}:{} (source: {})",
                        "Warning".yellow(),
                        rule.gid,
                        rule.sid,
                        source_name
                    );
                }
            }
        }

        if !quiet {
            let dataset_count = rules
                .values()
                .flat_map(|r| &r.datasets)
                .map(|d| &d.output_path)
                .collect::<std::collections::HashSet<_>>()
                .len();
            println!(
                "  Found {} dataset files",
                dataset_count.to_string().bright_black()
            );
        }

        Ok(ProcessedSource { rules })
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
        let cache_filename = format!("{url_hash}.tar.gz");
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

        let user_agent = UserAgent::new().to_string();
        debug!("Using User-Agent: {}", user_agent);
        let client = reqwest::blocking::Client::builder()
            .user_agent(user_agent)
            .build()?;
        let mut response = client
            .get(&url)
            .send()
            .with_context(|| format!("Failed to download {url}"))?;

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
        let progress_bar = if Self::is_tty() && !quiet {
            content_length.map(|content_length| {
                let progress_bar = ProgressBar::new(content_length);
                progress_bar.set_style(
                    ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                        .unwrap()
                        .progress_chars("#>-")
                );
                progress_bar
            })
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

    fn is_rules_file(filename: &str) -> bool {
        Path::new(filename)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rules"))
    }

    fn normalize_relative_path(path: &Path) -> Option<PathBuf> {
        let mut normalized = PathBuf::new();

        for component in path.components() {
            match component {
                Component::Normal(part) => normalized.push(part),
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() {
                        return None;
                    }
                }
                Component::RootDir | Component::Prefix(_) => {}
            }
        }

        Some(normalized)
    }

    #[cfg(test)]
    fn extract_dataset_load_paths(rule: &str) -> Vec<String> {
        let regex = Self::dataset_load_regex();

        regex
            .captures_iter(rule)
            .filter_map(|capture| capture.get(1))
            .map(|value| {
                value
                    .as_str()
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string()
            })
            .filter(|value| !value.is_empty())
            .collect()
    }

    fn dataset_load_regex() -> &'static Regex {
        static DATASET_LOAD_RE: OnceLock<Regex> = OnceLock::new();
        DATASET_LOAD_RE.get_or_init(|| {
            Regex::new(r"dataset\s*:[^;]*?\bload\s+([^,\s;]+)").expect("valid regex")
        })
    }

    fn path_to_rule_string(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn source_dataset_hash_path(source_name: &str, source_dataset_path: &Path) -> PathBuf {
        let identity = format!(
            "{}:{}",
            source_name,
            Self::path_to_rule_string(source_dataset_path)
        );
        let hash = format!("{:x}", md5::compute(identity.as_bytes()));
        Path::new(DATASETS_DIR).join(hash)
    }

    fn is_managed_dataset_name(name: &str) -> bool {
        name.len() == 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn should_cleanup_dataset_path(relative_path: &Path) -> bool {
        let Some(filename) = relative_path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };

        if !Self::is_managed_dataset_name(filename) {
            return false;
        }

        match relative_path.parent() {
            Some(parent) if parent == Path::new(DATASETS_DIR) => true,
            Some(parent) if parent == Path::new(DATASETS_DIR).join(LEGACY_MANAGED_DATASETS_DIR) => {
                true
            }
            _ => false,
        }
    }

    fn insert_rule_prefer_newer(rules: &mut HashMap<String, Rule>, key: String, rule: Rule) {
        match rules.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(rule);
            }
            Entry::Occupied(mut entry) => {
                if rule.rev > entry.get().rev {
                    entry.insert(rule);
                }
            }
        }
    }

    fn collect_dataset_files(rules: &HashMap<String, Rule>) -> HashMap<PathBuf, Vec<u8>> {
        let mut dataset_files: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        for rule in rules.values() {
            for dataset in &rule.datasets {
                match dataset_files.entry(dataset.output_path.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(dataset.content.clone());
                    }
                    Entry::Occupied(existing) => {
                        if existing.get() != &dataset.content {
                            eprintln!(
                                "{}: Dataset path collision for {} (keeping first file)",
                                "Warning".yellow(),
                                existing.key().display()
                            );
                        }
                    }
                }
            }
        }
        dataset_files
    }

    fn resolve_rule_datasets(
        source_name: &str,
        rule: &Rule,
        dep_files: &HashMap<PathBuf, Vec<u8>>,
    ) -> Result<Option<(String, Vec<ResolvedDataset>)>> {
        if !rule.enabled {
            return Ok(Some((rule.raw.clone(), Vec::new())));
        }

        let mut datasets: Vec<ResolvedDataset> = Vec::new();
        let mut rewritten_rule = String::with_capacity(rule.raw.len() + 32);
        let mut cursor = 0;

        for capture in Self::dataset_load_regex().captures_iter(&rule.raw) {
            let Some(dataset_token_match) = capture.get(1) else {
                continue;
            };
            let dataset_token = dataset_token_match.as_str();
            let dataset_name = dataset_token
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            if dataset_name.is_empty() {
                return Ok(None);
            }

            let dataset_path = Path::new(&dataset_name);
            if dataset_path.is_absolute() {
                continue;
            }

            let prefix = Path::new(&rule.group)
                .parent()
                .unwrap_or_else(|| Path::new(""));
            let source_filename = prefix.join(dataset_path);
            let source_filename = match Self::normalize_relative_path(&source_filename) {
                Some(path) => path,
                None => return Ok(None),
            };
            let content = dep_files.get(&source_filename).cloned();

            if let Some(content) = content {
                let output_path = Self::source_dataset_hash_path(source_name, &source_filename);
                let replacement = match (
                    dataset_token
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"')),
                    dataset_token
                        .strip_prefix('\'')
                        .and_then(|v| v.strip_suffix('\'')),
                ) {
                    (Some(_), _) => format!("\"{}\"", Self::path_to_rule_string(&output_path)),
                    (_, Some(_)) => format!("'{}'", Self::path_to_rule_string(&output_path)),
                    _ => Self::path_to_rule_string(&output_path),
                };

                rewritten_rule.push_str(&rule.raw[cursor..dataset_token_match.start()]);
                rewritten_rule.push_str(&replacement);
                cursor = dataset_token_match.end();

                datasets.push(ResolvedDataset {
                    output_path,
                    content,
                });
            } else {
                return Ok(None);
            }
        }

        if cursor == 0 {
            return Ok(Some((rule.raw.clone(), Vec::new())));
        }

        rewritten_rule.push_str(&rule.raw[cursor..]);
        Ok(Some((rewritten_rule, datasets)))
    }

    fn parse_rules(&self, group: &str, content: &[u8]) -> Result<Vec<Rule>> {
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
                        group: group.to_string(),
                        datasets: Vec::new(),
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

    fn write_dataset_files(&self, dataset_files: &HashMap<PathBuf, Vec<u8>>) -> Result<()> {
        for (relative_path, content) in dataset_files {
            let path = self.path_provider.rules_dir().join(relative_path);

            if let Some(parent) = path.parent() {
                crate::paths::ensure_dir_exists(parent).with_context(|| {
                    format!(
                        "Failed to create dataset directory {}: permission denied",
                        parent.display()
                    )
                })?;
            }

            fs::write(&path, content).with_context(|| {
                format!(
                    "Failed to write dataset file {}: permission denied",
                    path.display()
                )
            })?;
        }

        let dataset_paths: std::collections::HashSet<&PathBuf> = dataset_files.keys().collect();
        self.cleanup_unreferenced_dataset_files(&dataset_paths)?;

        Ok(())
    }

    fn cleanup_unreferenced_dataset_files(
        &self,
        dataset_paths: &std::collections::HashSet<&PathBuf>,
    ) -> Result<()> {
        let rules_dir = self.path_provider.rules_dir();
        let datasets_dir = rules_dir.join(DATASETS_DIR);
        let legacy_datasets_dir = datasets_dir.join(LEGACY_MANAGED_DATASETS_DIR);

        let read_root = match fs::read_dir(&datasets_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "Failed to read dataset directory {}",
                        datasets_dir.display()
                    )
                });
            }
        };

        for entry in read_root {
            let entry = entry.with_context(|| {
                format!(
                    "Failed to read entry in dataset directory {}",
                    datasets_dir.display()
                )
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("Failed to inspect dataset entry {}", path.display()))?;

            if !file_type.is_file() {
                continue;
            }

            let Ok(relative_path) = path.strip_prefix(&rules_dir).map(Path::to_path_buf) else {
                continue;
            };

            if !dataset_paths.contains(&relative_path)
                && Self::should_cleanup_dataset_path(&relative_path)
            {
                fs::remove_file(&path).with_context(|| {
                    format!("Failed to remove unreferenced dataset {}", path.display())
                })?;
            }
        }

        let mut dirs = Vec::new();
        let mut stack = vec![legacy_datasets_dir.clone()];

        while let Some(dir) = stack.pop() {
            let read_dir = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to read dataset directory {}", dir.display())
                    });
                }
            };
            dirs.push(dir.clone());
            for entry in read_dir {
                let entry = entry.with_context(|| {
                    format!(
                        "Failed to read entry in dataset directory {}",
                        dir.display()
                    )
                })?;
                let path = entry.path();
                let file_type = entry.file_type().with_context(|| {
                    format!("Failed to inspect dataset entry {}", path.display())
                })?;

                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }

                if !file_type.is_file() {
                    continue;
                }

                let Ok(relative_path) = path.strip_prefix(&rules_dir).map(Path::to_path_buf) else {
                    continue;
                };

                if !dataset_paths.contains(&relative_path)
                    && Self::should_cleanup_dataset_path(&relative_path)
                {
                    fs::remove_file(&path).with_context(|| {
                        format!("Failed to remove unreferenced dataset {}", path.display())
                    })?;
                }
            }
        }

        dirs.sort_by_key(|dir| Reverse(dir.components().count()));
        for dir in dirs {
            let mut entries = fs::read_dir(&dir)
                .with_context(|| format!("Failed to read dataset directory {}", dir.display()))?;
            if entries.next().is_none() {
                fs::remove_dir(&dir).with_context(|| {
                    format!("Failed to remove empty dataset directory {}", dir.display())
                })?;
            }
        }

        Ok(())
    }

    fn get_output_path(&self) -> PathBuf {
        self.path_provider.rules_dir().join(DEFAULT_OUTPUT_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::{Rule, UpdateManager};
    use crate::paths::PathProvider;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestPaths {
        root: PathBuf,
    }

    impl PathProvider for TestPaths {
        fn sources_dir(&self) -> PathBuf {
            self.root.join("sources")
        }

        fn cache_dir(&self) -> PathBuf {
            self.root.join("cache")
        }

        fn rules_dir(&self) -> PathBuf {
            self.root.join("rules")
        }
    }

    #[test]
    fn test_extract_dataset_load_paths() {
        let rule = r#"alert dns any any -> any any (msg:"test"; dataset:isset,myset,type string,load foo.lst; sid:1; rev:1;)"#;
        let paths = UpdateManager::extract_dataset_load_paths(rule);
        assert_eq!(paths, vec!["foo.lst"]);
    }

    #[test]
    fn test_normalize_relative_path() {
        let normalized =
            UpdateManager::normalize_relative_path(Path::new("rules/../lists/pawpatrules.lst"));
        assert_eq!(normalized.unwrap(), Path::new("lists/pawpatrules.lst"));

        let escaped = UpdateManager::normalize_relative_path(Path::new("../../evil.lst"));
        assert!(escaped.is_none());
    }

    #[test]
    fn test_source_dataset_hash_path_differs_by_source() {
        let source_dataset_path = Path::new("rules/foo.lst");
        let first = UpdateManager::source_dataset_hash_path("et/open", source_dataset_path);
        let second = UpdateManager::source_dataset_hash_path("pt/rules", source_dataset_path);
        assert_ne!(first, second);
    }

    #[test]
    fn test_resolve_rule_datasets_rewrites_load_path() {
        let rule = Rule {
            raw: r#"alert dns any any -> any any (msg:"test"; dataset:isset,myset,type string,load foo.lst; sid:1; rev:1;)"#.to_string(),
            enabled: true,
            sid: 1,
            gid: 1,
            rev: 1,
            group: "rules/test.rules".to_string(),
            datasets: Vec::new(),
            msg: "test".to_string(),
        };

        let mut dep_files = HashMap::new();
        dep_files.insert(PathBuf::from("rules/foo.lst"), b"one\ntwo\n".to_vec());

        let (rewritten, datasets) =
            UpdateManager::resolve_rule_datasets("et/open", &rule, &dep_files)
                .unwrap()
                .unwrap();

        let expected_path =
            UpdateManager::source_dataset_hash_path("et/open", Path::new("rules/foo.lst"));
        assert_eq!(datasets.len(), 1);
        assert_eq!(datasets[0].output_path, expected_path);
        assert_eq!(datasets[0].content, b"one\ntwo\n".to_vec());
        assert!(rewritten.contains(&format!(
            "load {}",
            UpdateManager::path_to_rule_string(&expected_path)
        )));
        assert!(!rewritten.contains("load foo.lst"));
    }

    #[test]
    fn test_resolve_rule_datasets_keeps_absolute_load_path() {
        let rule = Rule {
            raw: r#"alert dns any any -> any any (msg:"test"; dataset:isset,myset,type string,load /etc/shadow; sid:1; rev:1;)"#.to_string(),
            enabled: true,
            sid: 1,
            gid: 1,
            rev: 1,
            group: "rules/test.rules".to_string(),
            datasets: Vec::new(),
            msg: "test".to_string(),
        };

        let (rewritten, datasets) =
            UpdateManager::resolve_rule_datasets("et/open", &rule, &HashMap::new())
                .unwrap()
                .unwrap();

        assert_eq!(rewritten, rule.raw);
        assert!(datasets.is_empty());
    }

    #[test]
    fn test_resolve_rule_datasets_rewrites_relative_and_keeps_absolute_paths() {
        let rule = Rule {
            raw: r#"alert dns any any -> any any (msg:"test"; dataset:isset,myset,type string,load foo.lst; dataset:isset,otherset,type string,load /etc/shadow; sid:1; rev:1;)"#.to_string(),
            enabled: true,
            sid: 1,
            gid: 1,
            rev: 1,
            group: "rules/test.rules".to_string(),
            datasets: Vec::new(),
            msg: "test".to_string(),
        };

        let mut dep_files = HashMap::new();
        dep_files.insert(PathBuf::from("rules/foo.lst"), b"one\ntwo\n".to_vec());

        let (rewritten, datasets) =
            UpdateManager::resolve_rule_datasets("et/open", &rule, &dep_files)
                .unwrap()
                .unwrap();

        let expected_path =
            UpdateManager::source_dataset_hash_path("et/open", Path::new("rules/foo.lst"));
        assert_eq!(datasets.len(), 1);
        assert_eq!(datasets[0].output_path, expected_path);
        assert_eq!(datasets[0].content, b"one\ntwo\n".to_vec());
        assert!(rewritten.contains(&format!(
            "load {}",
            UpdateManager::path_to_rule_string(&expected_path)
        )));
        assert!(rewritten.contains("load /etc/shadow"));
    }

    #[test]
    fn test_collect_dataset_files_uses_winning_rule() {
        let mut rules = HashMap::new();

        let old_rule_dataset_path =
            UpdateManager::source_dataset_hash_path("source-old", Path::new("rules/foo.lst"));
        let new_rule_dataset_path =
            UpdateManager::source_dataset_hash_path("source-new", Path::new("rules/foo.lst"));

        let old_rule = Rule {
            raw: "alert ip any any -> any any (msg:\"old\"; sid:100; rev:1;)".to_string(),
            enabled: true,
            sid: 100,
            gid: 1,
            rev: 1,
            group: "rules/old.rules".to_string(),
            datasets: vec![super::ResolvedDataset {
                output_path: old_rule_dataset_path,
                content: b"old".to_vec(),
            }],
            msg: "old".to_string(),
        };

        let new_rule = Rule {
            raw: "alert ip any any -> any any (msg:\"new\"; sid:100; rev:2;)".to_string(),
            enabled: true,
            sid: 100,
            gid: 1,
            rev: 2,
            group: "rules/new.rules".to_string(),
            datasets: vec![super::ResolvedDataset {
                output_path: new_rule_dataset_path.clone(),
                content: b"new".to_vec(),
            }],
            msg: "new".to_string(),
        };

        UpdateManager::insert_rule_prefer_newer(&mut rules, "1:100".to_string(), old_rule);
        UpdateManager::insert_rule_prefer_newer(&mut rules, "1:100".to_string(), new_rule);

        let dataset_files = UpdateManager::collect_dataset_files(&rules);
        assert_eq!(dataset_files.len(), 1);
        assert_eq!(
            dataset_files.get(&new_rule_dataset_path),
            Some(&b"new".to_vec())
        );
    }

    #[test]
    fn test_write_dataset_files_only_cleans_managed_datasets() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("suricasta-rules-test-{unique}"));
        let paths = TestPaths { root: root.clone() };
        let manager = UpdateManager::new_with_suricata_version(&paths, Some("7.0.0"));

        let keep_rel = PathBuf::from("datasets/73905fd347807b03eec25846be7bd554");
        let stale_rel = PathBuf::from("datasets/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let unmanaged_rel = PathBuf::from("datasets/local.lst");

        fs::create_dir_all(paths.rules_dir().join("datasets")).unwrap();
        fs::write(paths.rules_dir().join(&stale_rel), b"stale").unwrap();
        fs::write(paths.rules_dir().join(&unmanaged_rel), b"outside datasets").unwrap();

        let mut dataset_files = HashMap::new();
        dataset_files.insert(keep_rel.clone(), b"keep".to_vec());

        manager.write_dataset_files(&dataset_files).unwrap();

        assert_eq!(
            fs::read(paths.rules_dir().join(&keep_rel)).unwrap(),
            b"keep".to_vec()
        );
        assert!(!paths.rules_dir().join(&stale_rel).exists());
        assert!(paths.rules_dir().join(&unmanaged_rel).exists());

        fs::remove_dir_all(&root).unwrap();
    }
}
