# Mutation gates

Ordinary pull-request checks always run the Linux and macOS Rust tests, formatting,
Clippy, Python reference tests, timeout diagnostics, real-daemon transport profiles,
and the packaged broker integration. Rust completion counts live in
`ci/ordinary-counts.json`; updating that census alone does not select mutation suites.

`ci/mutation-suites.json` registers each whole execution suite: 18 Rust executions
with 231 named mutants, plus the Python reference suite with 13. Reservation units
and live acceptance are separate modes. Each matrix job runs its unchanged script,
including that script's baselines, cached-artifact controls, nonces, source hashes,
mutant arms and restoration controls. Fixture-dependent jobs build the existing
revision-verified daemon fixtures. There is no dependency cache or shared target.

Pull requests select suites whose registered source anchors or named test files
changed. Common helpers, build manifests, toolchains, workflows and mutation scripts
select the full inventory. Unknown file classification also selects everything;
this deliberately prefers unnecessary work to an omitted gate. Documentation-only
and ordinary-census changes can select no mutation suite. Every main push, manual
workflow dispatch, and pull request carrying the `full-gates` label selects all 244
named mutants. Label changes trigger a new run; later commits retain full selection
while the label remains present. Manual dispatch uses the workflow available on the
default branch, so a new workflow must land before it can be dispatched. See
[GitHub’s manual dispatch documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).

The stable `mutation-completion` job verifies the exact selected receipt set,
registry and revision hashes, log hashes, suite completion markers and named mutant
execution lines. Header-deadline suites instead retain their existing structured
per-arm receipts, including the narrowly declared hang-class timeout verdict.
Missing, duplicate, stale or extra receipts, silent early returns, omitted named
mutants, changed inventories and unregistered scripts fail completion. A legitimate
empty selection succeeds without creating a matrix job or fabricating receipts.

When adding a mutant, update its registry labels, count, execution-output patterns
and script digest together. The digest records the reviewed inventory; it is not a
binary cache key. Keep mutation execution modes together with their existing
controls. Timeout diagnostic mutants and profile missing-fixture, wrong-revision,
cached-artifact, early-return and missing-case controls remain ordinary checks,
outside the 244 named-mutant count.
