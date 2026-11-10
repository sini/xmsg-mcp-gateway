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

#[derive(Debug, thiserror::Error)]
#[error("invalid logging configuration")]
struct LoggingConfigurationError;

fn logging_override(
    value: Result<String, std::env::VarError>,
) -> Result<Option<String>, LoggingConfigurationError> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(LoggingConfigurationError),
    }
}

fn default_subscriber<W>(
    writer: W,
    explicit: Option<&str>,
) -> Result<impl tracing::Subscriber + Send + Sync, LoggingConfigurationError>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::prelude::*;
    let filter: tracing_subscriber::filter::Targets = explicit
        .unwrap_or("warn,gateway_dispatch=info")
        .parse()
        .map_err(|_| LoggingConfigurationError)?;
    Ok(tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer)
            .with_filter(filter),
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    use tracing_subscriber::util::SubscriberInitExt;
    let subscriber = logging_override(std::env::var("RUST_LOG"))
        .and_then(|explicit| default_subscriber(std::io::stderr, explicit.as_deref()));
    match subscriber {
        Ok(subscriber) => subscriber.init(),
        Err(error) => {
            eprintln!("gateway command failed: {error}");
            std::process::exit(1);
        }
    }
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

#[cfg(test)]
mod logging_tests {
    #[test]
    fn actual_default_subscriber_enables_only_dispatch_info_and_existing_warnings() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        #[derive(Clone)]
        struct Captured(Arc<Mutex<Vec<u8>>>);
        impl Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
            type Writer = Captured;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        for (explicit, visible) in [(None, true), (Some("warn"), false)] {
            let capture = Captured(Arc::new(Mutex::new(Vec::new())));
            tracing::subscriber::with_default(
                super::default_subscriber(capture.clone(), explicit).unwrap(),
                || {
                    tracing::info!(target:"gateway_dispatch",operation="xmsg_send",class="pre_effect_unavailable",kind="not_found","dispatch outcome");
                    tracing::info!(target:"gateway_registration",address="CANARY_ADDRESS_34","CANARY_REGISTRATION_34");
                    tracing::warn!(target:"default_warning_control","existing warning retained");
                },
            );
            let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                text.contains("dispatch outcome"),
                visible,
                "actual subscriber ignored default/explicit filter: {text}"
            );
            assert!(
                !text.contains("CANARY_"),
                "default subscriber exposed other INFO data: {text}"
            );
            assert!(
                text.contains("existing warning retained"),
                "default subscriber lost existing WARN: {text}"
            );
            eprintln!(
                "actual-default-subscriber-control: explicit_warn={} {text}",
                explicit.is_some()
            );
        }
        let capture = Captured(Arc::new(Mutex::new(Vec::new())));
        assert!(super::default_subscriber(
            capture,
            Some("gateway_dispatch=CANARY_INVALID_LEVEL_34")
        )
        .is_err());
        assert_eq!(
            super::LoggingConfigurationError.to_string(),
            "invalid logging configuration"
        );
        assert!(super::logging_override(Err(std::env::VarError::NotPresent))
            .unwrap()
            .is_none());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            assert!(super::logging_override(Err(std::env::VarError::NotUnicode(
                std::ffi::OsString::from_vec(vec![0xff])
            )))
            .is_err());
        }
    }
}
