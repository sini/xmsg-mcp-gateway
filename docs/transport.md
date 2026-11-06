# Private xmsg transport foundation

`XmsgConfig` builds `xmsg::client::ClientOptions` and returns the shared client's
`RegisteredService`. It requires an explicit expected node and daemon UID. Socket
custody, wire types, frame bounds, deadlines, registration, list, keyed send,
reply, poll and ACK remain in xmsg's client library. There is no gateway wire
implementation or federation HTTP client.

The library revision, actual daemon source revision and baseline are recorded in
`ci/xmsg-pin.toml` and checked against Cargo.toml and Cargo.lock. The fixture
builder checks the checked-out Git revision before making its sole baseline
source change: embedding that revision in the CLI version. It builds both private
daemons from source. The client-only normal dependency graph excludes daemon
SQL, TLS and HTTP dependencies.

The mandatory Linux transport job runs eight cases against each revision,
including a test-profile guard. Seven completion markers additionally prevent an
early-return test from becoming a false success. Missing binaries, a mismatched
binary revision and a mismatched actual source revision must refuse. A copied
consumer with its expected-node check removed must fail the named node-mismatch
assertion. Portable unit tests run separately on Linux and macOS; the seven
Linux real-node cases deferred there all run in the mandatory transport job.

Federation tests generate an ephemeral CA and two certified nodes, with their own
private directories, databases, sockets and loopback listeners. Each admission
cell first delivers successfully, then refuses one explicit policy violation:
send permission, service principal, destination target or source IP/CIDR (`from`).
The source-IP case uses an observed loopback address outside the admitted range;
`from` is not an envelope identity field. Four single-site edits to the actual
pinned node's enforcement code must each make the corresponding negative cell
fail after its positive control passes. Build errors and timeouts are failures
of the mutation run, never accepted kills. Fixtures use no fleet credentials or
network endpoints. Service names remain plain parser-valid names.

This unit exposes no MCP messaging, subscriptions or custody. It does not wire
transport settings into the serving configuration. Discovery filtering and
per-operation dispatch policy belong to serving integration. Restart redelivery
here measures the node/client seam; it does not establish gateway durable custody
or its crash guarantees. Custody must still check TTL against actual pinned node
configuration, durably quarantine before ACK, define unbound-item treatment and
bound refusal retention with message-age loss warnings.

Live activation remains blocked by the owner choices recorded in the reviewed
contract and by the serving exposure preconditions in [serving.md](serving.md).
