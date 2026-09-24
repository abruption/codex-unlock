# Python safety prototype

This is an internal, non-distributable Python 3.12+ implementation used to
cross-check the Node.js `codex-unlock` safety boundary. It is not a PyPI
package, a supported CLI, or a replacement for the npm release. Do not point
it at a live Codex home. The tests create synthetic owners and homes only.

After `npm ci`, run `CODEX_UNLOCK_TEST_PYTHON=python3 npm run test:python-parity`.
The test suite reuses the Node fixture that holds a real advisory `flock`, and
validates Python results against the same JSON Schema v1. It compares stable
lock/owner/transcript evidence and policy decisions, exercises actual SIGTERM
of synthetic completed owners, and checks changes before signaling, the shared
operation lease, and post-signal verification failure. Dynamic timestamps,
platform error text, and observation order are not compared byte-for-byte.

The module is invoked by the test harness with an explicit temporary
`--codex-home`; there is no installed `codex-unlock` command. The hidden gate
options exist solely to make the race tests deterministic. A passing prototype
does not establish Python distribution support or authorize PyPI publication.
Windows and untested platforms remain unsupported.
