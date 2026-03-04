// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

pub mod cli;
pub mod paths;
pub mod rulesets;
pub mod sources;
pub mod update;
pub mod user_agent;

use anyhow::Result;

pub fn run(cli: cli::Cli) -> Result<()> {
    cli::run(cli)
}
