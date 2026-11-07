# Benchmarks

Measures a change against a baseline: real server, agent and application on one machine, in release
builds. The rules for when and how to measure are in "Performance rules" in
[CLAUDE.md](../../CLAUDE.md); what past measurements found is in "Threads and memory" in
[ARCHITECTURE.md](../../docs/ARCHITECTURE.md).

```bash
scripts/bench/build.sh base origin/main   # the version to beat
scripts/bench/build.sh new                # the working tree
scripts/bench/compare.sh base new         # takes turns, 3 rounds, about 8 minutes
```

```text
test                     base         new          change
small_c16 (req/s)        39,443 ±1%   49,259 ±1%   +25% better
small_file_c16 (req/s)   20,759 ±4%   20,874 ±6%   +1% better (runs overlap)
```

"Runs overlap" means the difference may be only noise. Failed and refused requests are listed under
the table. Raw results stay in `target/bench/results`.

Everything shares one machine, so numbers are only comparable to each other. Close what you can
first, and don't read much into a single round.

## Suites

Choose one with `compare.sh --suite <name>`, or run one build alone with `bench.sh <suite> <build dir>`.

| Suite | What it answers |
|---|---|
| `traffic` (default) | Requests, downloads, uploads, raw ports (with `iperf3`), small requests during downloads, static files, CPU per request |
| `control` | How much do tunnels slow down while the control plane is busy? Limits the server to 2 traffic threads so that it shows |
| `memory` | How much do the server and the agent hold after each kind of load, and after waiting? |
| `wan` | Over a shaped link: do downloads delay everyone else's requests? Needs `wan.sh` |
| `unix` | What does a Unix socket target cost, beside a port in the same build? Needs a build with `--unix` |
| `ssh` | What does the SSH gateway cost, beside sshd directly and a raw port? Needs a build with `--ssh`, and OpenSSH's server and client |

`BENCH_SECS` sets the seconds per measurement (default 3). `bench.sh` lists its other settings. The
scripts need Python 3, and they use their own home folder and ports, so an agent you're running
yourself is left alone.

## On Linux

Measure on static Linux as well, whatever you develop on. Production runs static musl builds, with
another allocator and other system calls than macOS or a glibc Linux. Cross-compile for the machine,
copy `scripts/bench` and the build folder over, and run it there:

```bash
# From a Mac, with `brew install filosottile/musl-cross/musl-cross` and
# `rustup target add aarch64-unknown-linux-musl`. For an x86-64 machine, use x86_64 throughout.
export CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
scripts/bench/build.sh base origin/main --target aarch64-unknown-linux-musl
scripts/bench/build.sh new --target aarch64-unknown-linux-musl
rsync -a scripts/bench target/bench/aarch64-unknown-linux-musl linux-box:mp/
```

```bash
# On the Linux machine:
BENCH_DIR=mp/aarch64-unknown-linux-musl mp/bench/compare.sh base new
```

Don't run this on a production server: `traffic` uses every core it can get.

## Over a slow link

Loopback hides queues. Anything touching the agent's session should also run over a shaped link, on
Linux, with `sudo` and `tc`:

```bash
scripts/bench/wan.sh on 20mbit 15ms 200        # rate, delay each way, queue in packets
BENCH_WAN_MB=12 scripts/bench/compare.sh --suite wan base new
scripts/bench/wan.sh off
```

Take downloads that last a few seconds: `BENCH_WAN_MB` is 64 by default, for 100 Mbit/s.

## Measuring something new

Add a `measure` line to a suite in `bench.sh`. The load generator is
`crates/magicpipes-bench/src/bin/load.rs` (`mp-bench-load --help`), and the application it talks to
is `app.rs` next to it. A line of output is `test=<name> key=<the number that matters> ...`, and
`summarize.py` needs nothing more than that.

`bench.sh control` seeds the database directly (`control.py`), so a schema change can break it. It
fails loudly when that happens: update the `INSERT`s.
