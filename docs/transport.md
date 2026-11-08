# Private xmsg transport foundation

`XmsgConfig` builds `xmsg::client::ClientOptions` and returns the shared client's
`RegisteredService`. It requires an explicit expected node and daemon UID. Socket
custody, wire types, frame bounds, deadlines, registration, list, keyed send,
reply, poll and ACK remain in xmsg's client library. There is no gateway wire
implementation or federation HTTP client.

The library revision and baseline daemon revision are recorded in
`ci/xmsg-pin.toml`. The library revision is checked against Cargo.toml and
Cargo.lock; both daemon revisions must be full commit IDs. The fixture
builder checks the checked-out Git revision before making its sole baseline
source change: embedding that revision in the CLI version. It builds both private
daemons from source. The client-only normal dependency graph excludes daemon
SQL, TLS and HTTP dependencies.

The mandatory Linux transport job requires nine cases against the pinned daemon,
including a test-profile guard and a socket-activation restart control. Eight
completion markers additionally prevent an early-return test from becoming a
false success. The previous 9b5bd5e daemon runs four Unix-socket cases: the profile
guard, registration/agent round trip, node mismatch and poll/ACK redelivery after
restart. Its five federation/socket-activation cases are explicitly filtered and
the count guard requires exactly four passed and five filtered. Federation returns
to the baseline lane when that baseline advances to a socket-activation daemon.
Missing binaries, a mismatched
binary revision and a mismatched actual source revision must refuse. A copied
consumer with its expected-node check removed must fail the named node-mismatch
assertion. Portable unit tests run separately on Linux and macOS.

The parent fixture holds the bound federation listener for the node's lifetime,
including restarts. It passes that listener through `LISTEN_FDS` with the name
`fed`, sets `LISTEN_PID` in the child before exec, and waits for `READY=1` on its
own `NOTIFY_SOCKET`. It never drops a listener and attempts to reclaim its port.
The old baseline creates only Unix sockets and waits for those sockets to appear;
it has no TCP fallback. The activation control keeps another ephemeral port
occupied and proves that both initial startup and restart use the held listener.

Federation tests generate an ephemeral CA and two certified nodes, with their own
private directories, databases, sockets and loopback listeners. Each admission
cell first delivers successfully, then refuses one explicit policy violation:
send permission, service principal, destination target or source IP/CIDR (`from`).
The source-IP case uses an observed loopback address outside the admitted range;
`from` is not an envelope identity field. Four single-site edits to the actual
pinned node's enforcement code must each make the corresponding negative cell
fail after its positive control passes. Build errors and timeouts are failures
of the mutation run, never accepted kills. Fixtures use no fleet credentials or
network endpoints. Service-name validity is enforced through xmsg's shared
validator at configuration load, before transport. The real-node
[`invalid_service_names_refuse_at_configuration_load`](../tests/messaging.rs)
cell covers that path.

The transport layer supplies the shared client boundary. The
[serving profile](serving.md#optional-messaging-profile) now wires it into configured
MCP send/reply, with discovery filtering and per-operation owner policy. Without
messaging configuration the listener opens no xmsg socket and serves identity
only. Restart redelivery in this transport profile measures the node/client seam;
it does not establish gateway durable custody or its crash guarantees. Those have
separate [inbound](custody.md) and [outbound](outbound.md) acceptance profiles.

Subscriptions, an inbound receiving worker and Rust Events remain outside the
current listener. Live deployment still requires the
[owner decisions and serving exposure preconditions](serving.md#deployment-boundaries).
