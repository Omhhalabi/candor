# Red Team tooling

Three things live here. One is a program, two are documents.

| File | What it is |
|---|---|
| [`candor.py`](candor.py) | **Candor.** One domain in, full attack-surface recon report out. Single file, stdlib only, 25 stages. Named for the Coverage section: it reports what it could not see, above what it found. |
| [`MANUAL-RECON-FIELD-GUIDE.html`](MANUAL-RECON-FIELD-GUIDE.html) | 15-chapter manual methodology for any domain, with the commands. For hunting without the tool. |
| [`OSINT-SITES.md`](OSINT-SITES.md) | 185 verified OSINT sites, plus the 32 dead ones named so you stop trying them. |

---

## Before the first packet

`candor.py` **has no scope logic, by design.** Whatever enumeration finds, it
touches — including a CNAME that lands on a vendor's CDN, a shared-hosting
neighbour, or your client's SaaS provider. **You own the rules of engagement.**

Grep the RoE for every host it discovers before you let it probe, and read the
out-of-scope list cross-brand: one company's exclusions are often written under
a different product name.

**No tier is passive.** Not even `light` — it sends HTTP to every host it finds,
fetches every JS asset, and collects staff names and email formats. The word
"passive" in the field guide means *no packet reaches the target*; this tool's
lowest tier is not that. Use `--dry-run` to see the plan without sending
anything.

---

## Install

Nothing to install. Python 3.9+ and the standard library.

```bash
python3 candor.py --selftest        # 110 offline checks, no network
```

External binaries (`subfinder`, `katana`, `nuclei`, `ffuf`, `naabu`) are
optional. If one is missing the tool downloads it from its GitHub release into
`~/.recon/bin` — no sudo, no Go toolchain. `--no-install` turns that off, and
every absent tool is then declared in the report's **Not tested** section
instead of silently producing a clean result.

```bash
python3 candor.py --toolcheck       # download, run and report each binary. No target.
```

Optional API keys go in `~/.recon/keys.env` (`KEY=value`, one per line) or the
environment. Each source is used only if its key is present, and is otherwise
listed as skipped:

```
SECURITYTRAILS_API_KEY  VIRUSTOTAL_API_KEY  SHODAN_API_KEY
CENSYS_API_ID  CENSYS_API_SECRET  CHAOS_API_KEY  GITHUB_TOKEN
HUNTER_API_KEY  GOOGLE_API_KEY  GOOGLE_CSE_ID
```

---

## Sample usage

**See what it would do, without touching the target.** Always the first run on
a new engagement.

```bash
python3 candor.py example.com --dry-run
```

**The default run.** OSINT, DNS, TLS, live-host probe, fingerprint, crawl, JS
and secret mining, conditional follow-ups, people, identity, AI surface.

```bash
python3 candor.py example.com
```

**Add port scanning and nuclei.**

```bash
python3 candor.py example.com --level scan
```

**Everything, loud.** Adds DNS permutation and ffuf content discovery. Tell the
client before you run this one.

```bash
python3 candor.py example.com --level full --threads 16
```

**Slow it right down** for a rate-limited or fragile target. `--rate` is
requests per second *per host*.

```bash
python3 candor.py example.com --rate 1 --threads 2 --timeout 25
```

**Pick up where a killed run stopped.** Reuses the newest run directory for
that domain and skips the stages already marked done. A stage that recorded
"I could not look" is never marked done, so `--resume` retries it.

```bash
python3 candor.py example.com --resume
```

**Run one stage only** — the usual way to re-test a single thing without a
390-second full pass.

```bash
python3 candor.py example.com --only followups,js_mine
```

```bash
python3 candor.py example.com --only email_auth,identity
```

**Skip the stages you have no authorisation for.**

```bash
python3 candor.py example.com --level scan --skip ports,people,leaks
```

**List the stages and their minimum level.**

```bash
python3 candor.py --list-stages
```

**Write somewhere other than `./recon-out`.**

```bash
python3 candor.py example.com -o /data/engagements/acme -q
```

### Levels

| Level | What it sends |
|---|---|
| `light` *(default)* | DNS + third-party OSINT, HTTP to every host found, full page and JS asset fetches, archived-build probes, staff-name and email collection. **Not passive.** |
| `scan` | Everything in `light`, plus TCP connect port scanning and nuclei templates against live hosts. |
| `full` | Everything in `scan`, plus DNS permutation and ffuf content discovery. Loud. |

`passive` is accepted as an alias for `light`, for old scripts. It is a bad name
for what that tier does and is kept only for compatibility.

### The 25 stages

`self_check`, `dns_apex`, `osint_keyless`, `osint_keyed`, `subfinder`,
`permute` *(full)*, `resolve`, `ip_intel`, `http_probe`, `tls`, `takeover`,
`ports` *(scan)*, `crawl`, `js_mine`, `history`, `followups`, `nuclei` *(scan)*,
`fuzz` *(full)*, `people`, `leaks`, `email_auth`, `identity`, `ai_surface`,
`correlate`, `triage`.

Any of these is a valid value for `--only` and `--skip`. `correlate` and
`triage` always re-run, even under `--resume`, because they summarise the whole
state and a stale summary is worse than none.

### Output

Each run writes to `<out>/<domain>/<YYYYmmdd-HHMMSS>/`:

| File | Contents |
|---|---|
| `report.md` | The report. Coverage section first, then findings by severity, then the asset graph and the attack plan. |
| `report.html` | The same report, standalone, for sending to someone. |
| `findings.json` | Findings only. A *derived* artifact — the store is `state.json`. |
| `state.json` | The run's whole state, including per-stage status. This is what `--resume` reads. |
| `raw/` | Every tool's raw output, per stage, so a finding can be traced back to the bytes that produced it. |

---

## Reading the report

**The Coverage section is printed above the findings, on purpose.** It names
every stage that had no instrument check, every external tool that was missing,
and every class of thing this run could not have seen. A clean report with 13
uninstrumented stages is not a clean target — it is a quiet instrument.

On the last verified run: 44 hosts, 28 IPs, 67 findings (1 high, 4 medium, 12
low, 50 info) from 2,536 direct HTTP requests, with 13 of 25 stages declared
uninstrumented by name and 16 untested classes.

Two things to know before filing anything from it:

- **Severity comes from the path's name, not the response body.** A `web.config`
  holding a connection string and one holding a rewrite rule score identically.
  Read the body before you believe the rating. (Known limitation, not yet fixed.)
- **A crashed handler declares itself.** If a follow-up handler raises, the
  report says so by handler and host in the *Not tested* section rather than
  reporting that host as clean. Earlier it did not, and one `NameError` silently
  removed 13 detectors on 14 hosts.

---

## Self-checks

```bash
python3 candor.py --selftest
```

110 offline checks, no network, no target. They include planted positives (can
each detector see something it should see?), negative controls (does it stay
quiet on bait?), suppression controls in both directions, and **structural
checks that assert against `candor.py`'s own source text** — those exist because
a fix applied to one of five call sites passed every other kind of test.

Run it after any edit. A failing structural check names the call site it found.
