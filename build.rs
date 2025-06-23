// SPDX-License-Identifier: AGPL-3.0-only
// SPDX-FileCopyrightText: Copyright 2025 Jason Ish <jason@codemonkey.net>

use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=embedded/index.yaml");
    println!("cargo:rerun-if-changed=embedded/timestamp.txt");

    let out_dir = env::var("OUT_DIR")?;
    let out_index_path = Path::new(&out_dir).join("index.yaml");
    let out_timestamp_path = Path::new(&out_dir).join("index-timestamp.txt");

    // Check if embedded files exist
    let embedded_index_path = Path::new("embedded/index.yaml");
    let embedded_timestamp_path = Path::new("embedded/timestamp.txt");

    if !embedded_index_path.exists() {
        eprintln!("Error: embedded/index.yaml not found!");
        eprintln!("Please run 'just update-embedded-index' to download the sources index.");
        std::process::exit(1);
    }

    // Copy the files to the output directory
    fs::copy(embedded_index_path, &out_index_path)?;

    // Copy timestamp if it exists, otherwise create one
    if embedded_timestamp_path.exists() {
        fs::copy(embedded_timestamp_path, &out_timestamp_path)?;
    } else {
        fs::write(&out_timestamp_path, chrono::Utc::now().to_rfc3339())?;
    }

    Ok(())
}
