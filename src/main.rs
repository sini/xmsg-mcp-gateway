use std::path::PathBuf;

use clap::{Parser, Subcommand};
use xmsg_mcp_gateway::grants::{Binding, Store};

#[derive(Parser)]
#[command(version, about = "Manage the gateway's local service grants")]
struct Cli {
    #[arg(long)]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Enroll { id: String, binding: PathBuf },
    Enable { id: String, revision: i64 },
    Disable { id: String, revision: i64 },
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Init => {
            Store::initialize(&cli.state)?;
            println!("authority store initialized");
        }
        Command::Enroll { id, binding } => {
            let binding: Binding = serde_json::from_slice(&std::fs::read(binding)?)?;
            Store::open(&cli.state)?.enroll(&id, &binding)?;
            println!("grant enrolled disabled at revision 1");
        }
        Command::Enable { id, revision } => {
            let next = Store::open(&cli.state)?.set_enabled(&id, revision, true)?;
            println!("grant enabled at revision {next}");
        }
        Command::Disable { id, revision } => {
            let next = Store::open(&cli.state)?.set_enabled(&id, revision, false)?;
            println!("grant disabled at revision {next}");
        }
    }
    Ok(())
}

fn main() {
    if run(Cli::parse()).is_err() {
        eprintln!("grant command failed; no success recorded");
        std::process::exit(1);
    }
}
