default:

check:
    cargo check --all-features --all-targets
    cargo check --all-features --all-targets --target x86_64-pc-windows-gnu
    cargo clippy --all-features --all-targets
    cargo clippy --all-features --all-targets --target x86_64-pc-windows-gnu
    cargo test

fix:
    cargo clippy --allow-dirty --fix --all-features
    cargo clippy --target x86_64-pc-windows-gnu --fix --all-features --allow-dirty
    cargo fmt
