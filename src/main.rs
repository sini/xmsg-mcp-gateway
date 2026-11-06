#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use xmsg_mcp_gateway::grants::{Binding, Error as GrantError, Store};

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

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error("cannot read enrollment binding document")]
    ReadBinding(#[source] std::io::Error),
    #[error("invalid enrollment binding document")]
    InvalidDocument(#[source] serde_json::Error),
}

fn run(cli: Cli) -> Result<(), CommandError> {
    match cli.command {
        Command::Init => {
            Store::initialize(&cli.state)?;
            println!("authority store initialized");
        }
        Command::Enroll { id, binding } => {
            let document = std::fs::read(binding).map_err(CommandError::ReadBinding)?;
            let binding: Binding =
                serde_json::from_slice(&document).map_err(CommandError::InvalidDocument)?;
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
    if let Err(error) = run(Cli::parse()) {
        eprintln!("grant command failed: {error}");
        std::process::exit(1);
    }
}
