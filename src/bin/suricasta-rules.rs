// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use clap::Parser;
use colored::Colorize;
use suricasta_rules::cli::Cli;

fn main() {
    if let Err(e) = suricasta_rules::run(Cli::parse()) {
        eprintln!("{}: {:#}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}
