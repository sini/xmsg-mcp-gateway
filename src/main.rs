#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use xmsg_mcp_gateway::grants::{Binding, Error as GrantError, Store};

#[derive(Parser)]
#[command(version, about = "Serve MCP and manage local service grants")]
struct Cli {
    #[arg(long)]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    Init,
    MigrateCustody,
    MigrateOutbound,
    SetOutboundPolicy {
        id: String,
        revision: i64,
        policy: PathBuf,
    },
    Enroll {
        id: String,
        binding: PathBuf,
    },
    Enable {
        id: String,
        revision: i64,
    },
    Disable {
        id: String,
        revision: i64,
    },
}

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("--state is required for owner grant commands")]
    MissingState,
    #[error("serve obtains its state path only from the owner configuration file")]
    UnexpectedState,
    #[error(transparent)]
    Configuration(#[from] xmsg_mcp_gateway::serving::ConfigurationError),
    #[error("MCP server failed")]
    Serve(#[source] std::io::Error),
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Custody(#[from] xmsg_mcp_gateway::custody::Error),
    #[error(transparent)]
    Outbound(#[from] xmsg_mcp_gateway::outbound::Error),
    #[error("cannot read enrollment binding document")]
    ReadBinding(#[source] std::io::Error),
    #[error("invalid enrollment binding document")]
    InvalidDocument(#[source] serde_json::Error),
    #[error("cannot read outbound policy document")]
    ReadPolicy(#[source] std::io::Error),
    #[error("invalid outbound policy document")]
    InvalidPolicy(#[source] serde_json::Error),
}

async fn run(cli: Cli) -> Result<(), CommandError> {
    match (cli.state, cli.command) {
        (state, Command::Serve { config }) => {
            if state.is_some() {
                return Err(CommandError::UnexpectedState);
            }
            xmsg_mcp_gateway::serving::Serving::from_owner_file(&config)?
                .serve()
                .await
                .map_err(CommandError::Serve)?;
        }
        (Some(state), Command::Init) => {
            Store::initialize(&state)?;
            println!("authority store initialized");
        }
        (Some(state), Command::MigrateCustody) => {
            Store::open(&state)?.migrate_custody()?;
            println!("custody schema migrated; startup remains unavailable");
        }
        (Some(state), Command::MigrateOutbound) => {
            Store::open(&state)?.migrate_outbound()?;
            println!("outbound schema migrated; startup remains unavailable");
        }
        (
            Some(state),
            Command::SetOutboundPolicy {
                id,
                revision,
                policy,
            },
        ) => {
            let document = std::fs::read(policy).map_err(CommandError::ReadPolicy)?;
            let policy = serde_json::from_slice(&document).map_err(CommandError::InvalidPolicy)?;
            let next = Store::open(&state)?.set_outbound_policy(&id, revision, &policy)?;
            println!("outbound policy changed at revision {next}");
        }
        (Some(state), Command::Enroll { id, binding }) => {
            let document = std::fs::read(binding).map_err(CommandError::ReadBinding)?;
            let binding: Binding =
                serde_json::from_slice(&document).map_err(CommandError::InvalidDocument)?;
            Store::open(&state)?.enroll(&id, &binding)?;
            println!("grant enrolled disabled at revision 1");
        }
        (Some(state), Command::Enable { id, revision }) => {
            let next = Store::open(&state)?.set_enabled(&id, revision, true)?;
            println!("grant enabled at revision {next}");
        }
        (Some(state), Command::Disable { id, revision }) => {
            let next = Store::open(&state)?.set_enabled(&id, revision, false)?;
            println!("grant disabled at revision {next}");
        }
        (None, _) => return Err(CommandError::MissingState),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("gateway command failed: {error}");
        std::process::exit(1);
    }
}
