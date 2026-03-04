// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use crate::paths::PathProvider;
use crate::rulesets::RulesetManager;
use crate::sources::SourceManager;
use crate::update::UpdateManager;
use anyhow::Result;
use clap::builder::styling::{AnsiColor, Color, Style};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "suricasta-rules")]
#[command(about = "Suricata Rule Manager")]
#[command(version)]
#[command(styles = get_styles())]
#[command(args_conflicts_with_subcommands = false)]
#[command(subcommand_precedence_over_arg = true)]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Use user-specific directories instead of system directories"
    )]
    pub user: bool,

    #[arg(
        short = 'v',
        long = "verbose",
        global = true,
        action = clap::ArgAction::Count,
        help = "Increase verbosity (can be used multiple times)"
    )]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Update rule sources and rulesets")]
    Update {
        #[arg(
            short = 'f',
            long = "force",
            help = "Force download even if cache is recent"
        )]
        force: bool,
        #[arg(short = 'q', long = "quiet", help = "Only output warnings and errors")]
        quiet: bool,
        #[arg(
            long = "suricata-version",
            help = "Suricata version to use when resolving source URLs (auto-detected from suricata -V, falls back to 7.0.0)"
        )]
        suricata_version: Option<String>,
    },

    #[command(about = "Enable a ruleset")]
    EnableRuleset {
        #[arg(help = "Name of the ruleset to enable")]
        name: Option<String>,
    },
    #[command(about = "Disable a ruleset")]
    DisableRuleset {
        #[arg(help = "Name of the ruleset to disable")]
        name: Option<String>,
    },
    #[command(about = "Update rule sources")]
    UpdateSources,
}

pub fn run(cli: Cli) -> Result<()> {
    init_logging(cli.verbose);

    let user = cfg!(target_os = "windows") || cli.user;
    let path_provider = crate::paths::get_path_provider(user);

    run_with_path_provider(&cli.command, path_provider.as_ref())
}

pub fn run_with_path_provider(command: &Commands, path_provider: &dyn PathProvider) -> Result<()> {
    match command {
        Commands::Update {
            force,
            quiet,
            suricata_version,
        } => update_rules_with_suricata_version(
            path_provider,
            *force,
            *quiet,
            suricata_version.as_deref(),
        ),
        Commands::EnableRuleset { name } => {
            let source_manager = SourceManager::new(path_provider);
            let ruleset_manager = RulesetManager::new(path_provider);

            let source_index = source_manager.get_or_download_index()?;

            let source_name = match name {
                Some(n) => n.clone(),
                None => match ruleset_manager.select_source(&source_index)? {
                    Some(n) => n,
                    None => return Ok(()),
                },
            };

            let source_info = source_index
                .sources
                .get(&source_name)
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", source_name))?;

            ruleset_manager.enable_source(&source_name, Some(source_info))
        }
        Commands::DisableRuleset { name } => {
            let ruleset_manager = RulesetManager::new(path_provider);

            let source_name = match name {
                Some(n) => n.clone(),
                None => match ruleset_manager.select_enabled_source()? {
                    Some(n) => n,
                    None => return Ok(()),
                },
            };

            ruleset_manager.disable_source(&source_name)
        }
        Commands::UpdateSources => update_sources(path_provider),
    }
}

pub fn update_rules(path_provider: &dyn PathProvider, force: bool, quiet: bool) -> Result<()> {
    update_rules_with_suricata_version(path_provider, force, quiet, None)
}

pub fn update_rules_with_suricata_version(
    path_provider: &dyn PathProvider,
    force: bool,
    quiet: bool,
    suricata_version: Option<&str>,
) -> Result<()> {
    let update_manager = UpdateManager::new_with_suricata_version(path_provider, suricata_version);
    update_manager.update(force, quiet)
}

pub fn update_sources(path_provider: &dyn PathProvider) -> Result<()> {
    let source_manager = SourceManager::new(path_provider);
    source_manager.update_sources()
}

pub fn enable_ruleset(path_provider: &dyn PathProvider, name: &str) -> Result<()> {
    let source_manager = SourceManager::new(path_provider);
    let ruleset_manager = RulesetManager::new(path_provider);

    let source_index = source_manager.get_or_download_index()?;
    let source_info = source_index
        .sources
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", name))?;

    ruleset_manager.enable_source(name, Some(source_info))
}

pub fn disable_ruleset(path_provider: &dyn PathProvider, name: &str) -> Result<()> {
    let ruleset_manager = RulesetManager::new(path_provider);
    ruleset_manager.disable_source(name)
}

pub fn enabled_rulesets(path_provider: &dyn PathProvider) -> Result<Vec<String>> {
    let ruleset_manager = RulesetManager::new(path_provider);
    ruleset_manager.get_enabled_sources()
}

pub fn init_logging(verbose: u8) {
    let log_level = match verbose {
        0 => "suricasta_rules=info",
        1 => "suricasta_rules=debug",
        _ => "suricasta_rules=trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(log_level))
        .init();
}

fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Blue))),
        )
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))))
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
}
