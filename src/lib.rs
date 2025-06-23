// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

pub mod cli;
pub mod paths;
pub mod rulesets;
pub mod sources;
pub mod update;

use anyhow::Result;

pub fn run(cli: cli::Cli) -> Result<()> {
    let path_provider = paths::get_path_provider(cli.user);

    match cli.command {
        cli::Commands::Update { force, quiet } => {
            let update_manager = update::UpdateManager::new(path_provider.as_ref());
            update_manager.update(force, quiet)
        }

        cli::Commands::EnableRuleset { name } => {
            let source_manager = sources::SourceManager::new(path_provider.as_ref());
            let ruleset_manager = rulesets::RulesetManager::new(path_provider.as_ref());

            let source_index = source_manager.get_index()?;

            let source_name = match name {
                Some(n) => n,
                None => match ruleset_manager.select_source(&source_index)? {
                    Some(n) => n,
                    None => return Ok(()),
                },
            };

            let source_info = source_index.sources.get(&source_name);
            if source_info.is_none() {
                return Err(anyhow::anyhow!("Unknown ruleset: {}", source_name));
            }

            ruleset_manager.enable_source(&source_name, source_info)
        }
        cli::Commands::DisableRuleset { name } => {
            let ruleset_manager = rulesets::RulesetManager::new(path_provider.as_ref());

            let source_name = match name {
                Some(n) => n,
                None => match ruleset_manager.select_enabled_source()? {
                    Some(n) => n,
                    None => return Ok(()),
                },
            };

            ruleset_manager.disable_source(&source_name)
        }
        cli::Commands::UpdateSources => {
            let source_manager = sources::SourceManager::new(path_provider.as_ref());
            source_manager.update_sources()
        }
    }
}
