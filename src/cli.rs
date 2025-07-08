// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

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
