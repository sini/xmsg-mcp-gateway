# Control and mutation artifacts

Copied consumer controls previously preserved source mtimes and reused a persistent
Cargo target without checking freshness. A second run could execute the preceding
expected-node mutant: an unchanged source hash reported `fresh=true` and accepted
the wrong node; touching that same file reported `fresh=false` and refused it.
Those copied-consumer results are unverified until rerun with these guards.

Transport, inbound and outbound controls now copy source without preserving mtimes,
use temporary targets distinct for each variant, and require both the gateway
library and selected test executable to report `fresh=false`. Each profile also
rebuilds an unchanged control deliberately and requires the cache guard to refuse
it. A compilation failure or unrelated assertion cannot satisfy that self-test.

Grant, identity, serving, inbound and outbound mutation drivers use a separate
builder. They already required the changed library or application to rebuild;
the selected test executable must now rebuild too. Identity and serving copies
also discard source mtimes. Federation mutation builds already require the daemon
executable to rebuild. Python mutation arms execute in new interpreter processes.

Every observed Rust mutation/control executable logs a run nonce, path, nanosecond
mtime, executable SHA256 and source SHA256. A driver refuses the same executable
hash for different source variants. Repeated executions of the identical baseline
are allowed. Shared dependency caches do not substitute for these artifact checks.
CI shares targets within jobs, so the same guards apply there. Historical copied
consumer results cannot be recovered from their success status; reruns provide
new evidence. Independently isolated reviewer mutations remain separate evidence.
