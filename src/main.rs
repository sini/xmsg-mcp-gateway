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
    EventsRebind {
        #[arg(long)]
        config: PathBuf,
        id: String,
        generation: i64,
        #[arg(long)]
        callback_file: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        cursor: Option<String>,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
    },
    EventsReplay {
        #[arg(long)]
        config: PathBuf,
        id: String,
        generation: i64,
        #[arg(
            long,
            allow_hyphen_values = true,
            conflicts_with = "release_items_file"
        )]
        cursor: Option<String>,
        #[arg(long, conflicts_with = "cursor")]
        release_items_file: Option<PathBuf>,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
    },
    Init,
    MigrateCustody,
    MigrateOutbound,
    MigrateRetirement,
    MigrateEvents {
        #[arg(long)]
        key_file: PathBuf,
    },
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
    #[error("configuration-based commands obtain state only from the owner configuration file")]
    UnexpectedState,
    #[error(transparent)]
    Configuration(#[from] xmsg_mcp_gateway::serving::StartupError),
    #[error("MCP server failed")]
    Serve(#[source] std::io::Error),
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Events(#[from] xmsg_mcp_gateway::event_store::Error),
    #[error(transparent)]
    EventLifecycle(#[from] xmsg_mcp_gateway::events::Error),
    #[error("invalid or unavailable private owner document")]
    OwnerDocument,
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
            xmsg_mcp_gateway::serving::Serving::from_owner_file(&config)
                .await?
                .serve()
                .await
                .map_err(CommandError::Serve)?;
        }
        (
            state,
            Command::EventsRebind {
                config,
                id,
                generation,
                callback_file,
                cursor,
                operator,
                reason,
            },
        ) => {
            if state.is_some() {
                return Err(CommandError::UnexpectedState);
            }
            let url = String::from_utf8(private_document(&callback_file, 4096)?)
                .map_err(|_| CommandError::OwnerDocument)?;
            let result = xmsg_mcp_gateway::serving::owner_events(&config)?.rebind(
                &id,
                generation,
                url.trim(),
                cursor.as_deref(),
                &operator,
                &reason,
            )?;
            println!("{result}");
        }
        (
            state,
            Command::EventsReplay {
                config,
                id,
                generation,
                cursor,
                release_items_file,
                operator,
                reason,
            },
        ) => {
            if state.is_some() {
                return Err(CommandError::UnexpectedState);
            }
            let events = xmsg_mcp_gateway::serving::owner_events(&config)?;
            let result = if let Some(file) = release_items_file {
                let items: Vec<String> =
                    serde_json::from_slice(&private_document(&file, 512 * 1024)?)
                        .map_err(|_| CommandError::OwnerDocument)?;
                events.release_selected(&id, generation, &items, &operator, &reason)?
            } else {
                events.replay(&id, generation, cursor.as_deref(), &operator, &reason)?
            };
            println!("{result}");
        }
        (Some(state), Command::Init) => {
            Store::initialize(&state)?;
            println!("authority store initialized");
        }
        (Some(state), Command::MigrateCustody) => {
            Store::open(&state)?.migrate_custody()?;
            println!("custody schema migrated; worker startup remains unavailable");
        }
        (Some(state), Command::MigrateEvents { key_file }) => {
            let key = xmsg_mcp_gateway::event_store::EventKey::load(&key_file)?;
            Store::open(&state)?.migrate_events(&key)?;
            println!("Events schema migrated");
        }
        (Some(state), Command::MigrateRetirement) => {
            Store::open(&state)?.migrate_retirement()?;
            println!("outbound retirement schema migrated");
        }
        (Some(state), Command::MigrateOutbound) => {
            Store::open(&state)?.migrate_outbound()?;
            println!("outbound schema migrated");
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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("gateway command failed: {error}");
        std::process::exit(1);
    }
}

fn private_document(file: &std::path::Path, limit: u64) -> Result<Vec<u8>, CommandError> {
    use std::io::Read;
    let mut input = std::fs::File::open(file).map_err(|_| CommandError::OwnerDocument)?;
    let metadata = input.metadata().map_err(|_| CommandError::OwnerDocument)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CommandError::OwnerDocument);
        }
    }
    if !metadata.is_file() || metadata.len() > limit {
        return Err(CommandError::OwnerDocument);
    }
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError::OwnerDocument)?;
    if bytes.len() as u64 > limit {
        return Err(CommandError::OwnerDocument);
    }
    Ok(bytes)
}
