# Recon & OSINT sites — verified catalogue

Companion to [`candor.py`](candor.py). **Everything below was status-checked on 2026-11-24**, not copied from a roundup. OSINT lists rot fast: **32 services that still appear in popular "awesome" lists, 2026 blog posts and default `subfinder`/`amass` configs are dead or repurposed** — they are in [§15](#15-dead--removed--recognise-these-in-old-guides) so you recognise them instead of losing an engagement day to them. Three of them were wired into `candor.py` until this research found them.

## Legend

| Mark | Meaning |
|---|---|
| `[AUTO]` | `candor.py` already queries this — don't do it by hand |
| `[KEYLESS]` | returns real data to an unauthenticated request; scriptable today |
| `[KEY]` | needs an account/API key |
| `[BROWSER]` | works in a browser but blocks scripted clients (Cloudflare etc.) |
| `[TOUCHY]` | legal/ethical exposure — get it into the RoE before you use it |
| `[UPLOADS]` | **using it with our data discloses that data to a third party** |

Two rules this list assumes, both learned the hard way:

1. **A source returning nothing is not evidence of nothing.** Half the entries here answer `403`/`429` to automation while working fine in a browser. `candor.py` now prints the HTTP status per source for exactly this reason.
2. **Public scanners publish.** urlscan.io, SSL Labs, securityheaders, ImmuniWeb and every malware sandbox default to public results. Tick the hide/private box, or don't submit.

---

## 1. Certificate transparency

CT logs are the highest-yield free subdomain source and the fastest way to spot a typosquat or a shadow asset the moment its cert is issued.

| Site | Access | Good for |
|---|---|---|
| [crt.sh](https://crt.sh/) `?q=%25.domain&output=json` | `[AUTO]` `[KEYLESS]` | The canonical CT search. **502s under load and can take >40s** — `candor.py` uses a 60s timeout after a 40s one produced a false zero. Also exposes raw Postgres (`psql -h crt.sh`). |
| [api.certspotter.com](https://api.certspotter.com/v1/issuances) | `[AUTO]` `[KEYLESS]` | Cleanest CT JSON, `include_subdomains` + `expand=dns_names`. ~100 queries/hr/IP then 429. The fallback when crt.sh is down. |
| [Merklemap](https://www.merklemap.com/) | `[KEY]` | Newer full-CT index with wildcard/regex search; often better recall than crt.sh. API path unconfirmed — check their docs. |
| [CertStream](https://certstream.calidog.io) | `[KEYLESS]` | **Real-time** CT firehose over WebSocket. The right instrument for continuous typosquat watch rather than daily diffing. No uptime guarantee — a dropped socket is a silently disabled detector, so reconnect logic is mandatory. |
| [Censys certificate search](https://platform.censys.io/) | `[KEY]` `[BROWSER]` | Best cert-field pivoting (SAN, issuer, fingerprint, `cert.added_at`) — but see the Censys warning in §3. |

## 2. Passive DNS & subdomain sources

| Site | Access | Good for |
|---|---|---|
| [api.subdomain.center](https://api.subdomain.center/?domain=example.com) | `[AUTO]` `[KEYLESS]` | Independent crawl; **the single best contributor on our own estate** (32 unique names, 17 that nothing else found). Added to `candor.py` as a result of this research. |
| [HackerTarget](https://api.hackertarget.com/hostsearch/?q=) | `[AUTO]` `[KEYLESS]` | A dozen one-URL plaintext tools (`hostsearch`, `dnslookup`, `reverseiplookup`, `httpheaders`). **Signals quota exhaustion as plain text inside an HTTP 200** — parse the body, not the status. |
| [RapidDNS](https://rapiddns.io/subdomain/example.com?full=1) | `[AUTO]` `[KEYLESS]` (HTML) | Big passive dump, no account. Scrape the table; no JSON endpoint. |
| [urlscan.io](https://urlscan.io/api/v1/search/?q=domain:example.com) | `[AUTO]` `[KEYLESS]` | Historical page scans by others — resolved hostnames, requested domains, screenshots. Finds subdomains nobody else indexed. **Submissions are world-readable: never submit an authenticated URL.** |
| [AlienVault OTX / LevelBlue](https://otx.alienvault.com/) | `[AUTO]` `[KEYLESS]`, throttled | Passive DNS + URL list per domain. **429s keyless from a busy IP** — our runs hit this consistently; register a free key. |
| [VirusTotal](https://www.virustotal.com/) `/api/v3/domains/{d}/subdomains` | `[AUTO]` `[KEY]` | Aggregated passive DNS + sibling-domain pivots. Free key = 4 req/min, 500/day. The undocumented UI endpoint is throttled to 429. |
| [SecurityTrails](https://securitytrails.com/) | `[AUTO]` `[KEY]` `[BROWSER]` | Deepest historical DNS and reverse-NS. **The generous free API tier is gone** — subdomain enumeration is now a paid feature. |
| [DNSDumpster](https://dnsdumpster.com/) | `[BROWSER]` / `[KEY]` | One-page visual DNS map + host table. **API now needs a free account key** (`api.dnsdumpster.com` → 401). Same operator as HackerTarget. |
| [Robtex](https://freeapi.robtex.com/ipquery/) | `[KEYLESS]` | Reverse-IP / shared-hosting passive DNS with ASN + BGP route in one record. Streams NDJSON on some endpoints. |
| [DNSlytics](https://dnslytics.com/) | `[KEY]`, daily cap | Reverse-IP, reverse-analytics, reverse-AdSense, shared-nameserver pivots. **The best surviving SpyOnWeb substitute.** |
| [Chaos (ProjectDiscovery)](https://cloud.projectdiscovery.io) | `[AUTO]` `[KEY]` | Huge precomputed bug-bounty-scope dataset. **No longer keyless** — now needs a PD cloud token. |
| [Netlas](https://netlas.io) | `[KEY]` | CT + host + DNS in one query language; 50 free requests/day. Good Shodan substitute. |
| [nmmapper](https://www.nmmapper.com/) | free web | Runs sublist3r/amass for you — useful when you want tool output without installing tools. |
| [DNSHistory.org](https://dnshistory.org/) | `[KEYLESS]` (HTML) | Long-tail historical A/NS records going back years. Thin, but sometimes the only source for a 2012-era record. |
| [CompleteDNS](https://completedns.com/) | `[KEY]` | Nameserver-change history — catches infrastructure migrations. |

## 3. Internet-wide scanners

| Site | Access | Good for |
|---|---|---|
| [Shodan InternetDB](https://internetdb.shodan.io/) | `[AUTO]` `[KEYLESS]` | **Per-IP open ports + hostnames + CPEs + CVEs, no account, no credits.** The best no-account exposure check that exists. Now wired into `candor.py`, so even a `passive` run gets port data without sending a packet to the target. |
| [Shodan](https://www.shodan.io/) | `[KEY]` | Deepest filter vocabulary + screenshots. **Free is a demo**: any filter or page ≥2 spends a credit, `vuln:` needs a higher tier. The $49 Membership is one-time, not a subscription — best-value paid entry on this list. |
| [Censys Platform](https://platform.censys.io/) | `[KEY]` `[BROWSER]` | Highest-fidelity host/service/cert data. **Breaking change: legacy `search.censys.io` is deprecated (full removal Sept 2026), free accounts cannot call the search API at all — lookup only — and the old `censys-python` SDK no longer authenticates.** Anything built on legacy Censys needs replanning now; `candor.py`'s Censys source is affected. |
| [Netlas](https://netlas.io) | `[KEY]` | Best free-tier response-body search. |
| [ZoomEye](https://zoomeye.ai/) | `[KEY]` | Strongest Asian-infrastructure coverage. **Moved to `.ai`**; API base `api.zoomeye.ai/v2`, simple `API-KEY` header (not the old JWT), SDK `zoomeyeai`. |
| [FOFA](https://en.fofa.info/) | `[KEY]` | Favicon / body / cert fingerprint pivoting — fastest way to find every host running one panel. Query must be base64-encoded. |
| [Criminal IP](https://www.criminalip.io/) | `[KEY]` | Asset search with risk scoring and exposed-login detection. |
| [Hunter.how](https://hunter.how/) | `[KEY]` | Cheap scanner alternative, good cert/web-asset search. |
| [Odin](https://odin.io/) | `[KEY]` | Newer engine, generous free tier while it grows. |
| [GreyNoise Community](https://api.greynoise.io/v3/community/) | `[KEYLESS]` | Is this IP mass-scanning noise or RIOT/benign — triage before you chase it. Note the exact path; other v3 paths need a key. |

## 4. IP, ASN & routing

| Site | Access | Good for |
|---|---|---|
| [RIPEstat](https://stat.ripe.net/) `data/<endpoint>/data.json` | `[AUTO]` `[KEYLESS]` | Announced prefixes, whois, routing history, RPKI, abuse contacts — machine-readable ASN truth. **Now `candor.py`'s ASN source, replacing the dead BGPView.** `network-info` for IP→ASN+prefix, `as-overview` for the holder name. |
| [bgp.he.net](https://bgp.he.net/) | free (HTML) | De-facto free ASN browser: ASN → prefixes, peers, upstreams. No JSON API — scrape, or use RIPEstat. |
| [bgp.tools](https://bgp.tools/) | `[KEYLESS]` with caveat | Best modern BGP UI; `table.jsonl` bulk dump works keyless **but only with a descriptive User-Agent** — a default/absent UA gets 403. Named successor to BGPView. |
| [ipctl.io](https://ipctl.io/) | `[KEY]` | Positions itself explicitly as the BGPView replacement. |
| [ipinfo.io](https://ipinfo.io/8.8.8.8/json) | `[KEYLESS]` then `[KEY]` | Fastest clean geo + `org`/ASN, includes `anycast`. ~1k/day keyless. |
| [AbuseIPDB](https://www.abuseipdb.com/) | `[KEY]` `[BROWSER]` | Crowd-sourced abuse reports + confidence score. Free key = 1,000 checks/day. |
| [Scamalytics](https://scamalytics.com/ip/) | free web | Blunt fraud-risk score per IP, readable with no account. API is key-bound. |
| [Spur.us](https://spur.us/) | `[KEY]` | Identifies VPN/proxy/residential-proxy infrastructure **by operator name** — unmatched for "is this traffic anonymised". Essentially enterprise. |
| [WiGLE](https://wigle.net/) | `[KEY]` | SSID/BSSID → physical location. Niche for domain recon, essential for physical/wireless scoping. |

## 5. WHOIS & registration

| Site | Access | Good for |
|---|---|---|
| [rdap.org](https://rdap.org/domain/example.com) | `[AUTO]` `[KEYLESS]` | Universal RDAP redirector — one URL, any TLD, structured JSON. Returns **302**, so follow redirects. The modern replacement for port-43 WHOIS scraping. |
| [Verisign RDAP](https://rdap.verisign.com/com/v1/domain/) | `[KEYLESS]` | Direct structured JSON for .com/.net, no rate-limit games. |
| [ICANN Lookup](https://lookup.icann.org/) | free | Authoritative, neutral, no upsell. |
| [DomainTools](https://whois.domaintools.com/) | `[KEY]` | **Still the gold standard for attribution**: WHOIS history and reverse-WHOIS (registrant email → all their domains). Everything useful is behind Iris at enterprise pricing. |
| [WhoisXMLAPI](https://www.whoisxmlapi.com/) | `[KEY]` | Broad catalogue under one key: WHOIS history, reverse WHOIS, reverse NS/MX, DNS history. Free tier is a one-off credit grant per product. |
| [WhoisFreaks](https://whoisfreaks.com/) | `[KEY]` | Cheaper competitor; bulk + reverse WHOIS + newly-registered-domain feeds. |
| [Whoisology](https://whoisology.com/) | `[KEY]` `[BROWSER]` | Reverse-WHOIS by any single field (email, phone, street, name). Nearly all connection data now paywalled. |
| [ViewDNS.info](https://viewdns.info/) | `[BROWSER]` | 16 tools on one page: reverse IP/NS/MX, IP history, DNS report, propagation. **Tool URLs now 403 to scripts and the API 401s — browser only, do not script the HTML.** |
| [BuiltWith](https://builtwith.com/) | `[KEY]` | Technology profile plus **Relationships** (shared analytics/ad IDs → sibling domains) — the strongest co-ownership pivot left, and a technology *timeline* for dating a legacy component. |

## 6. Archives — recover what was deleted but never rotated

| Site | Access | Good for |
|---|---|---|
| [Wayback CDX API](https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json&collapse=urlkey) | `[AUTO]` `[KEYLESS]` | **Enumerate every historical URL for a domain**, including withdrawn `.env`, `.git`, `.map` and backup paths. Arguably the highest-value single entry here: it recovers secrets deleted from the live site but never rotated. Note it yields one netloc per URL, so raw row counts wildly overstate how many distinct hosts it found. |
| [Wayback Machine](https://web.archive.org) | `[KEYLESS]` | Fetch the archived body of a dead URL found via CDX. CDX lists, Wayback fetches. |
| [archive.org advancedsearch](https://archive.org/advancedsearch.php?q=&output=json) | `[KEYLESS]` | Searches **item metadata** — uploaded dumps, leak archives, mirrors. A different corpus from Wayback; most people miss it. |
| [Common Crawl](https://index.commoncrawl.org) | `[KEYLESS]` | Petabyte crawl index; catches paths Wayback never captured. Get the index list from `collinfo.json`, then query `CC-MAIN-YYYY-WW-index?url=*.domain&output=json`. |
| [archive.today](https://archive.ph) | `[BROWSER]` | Captures pages Wayback honours robots-exclusion on. Cloudflare-gated; domains rotate (`.ph`/`.is`/`.li`/`.vn`/`.md`). |

> **Google's cache is gone.** Retired in 2024. Drop every `cache:` dork; CachedView now just queries Wayback.

## 7. Code, secret & leak search

| Site | Access | Good for |
|---|---|---|
| [grep.app](https://grep.app) | `[AUTO]` `[KEYLESS]` | Exact-string/regex hunt for a leaked key across ~1M repos, no login. **Rate-limits to 429 aggressively** — `candor.py` now reports the status rather than treating a throttle as "no leaks". |
| [GitHub code search](https://github.com/search?type=code) | `[KEY]` | `org:`/`user:`/`path:` over 800M+ repos. **Login-walled since 2023** — unauth API returns 401. |
| [Sourcegraph](https://sourcegraph.com/search) | `[KEY]`, free for public code | Structural + regex search over 2M+ OSS repos. |
| [searchcode.com](https://searchcode.com) | `[KEYLESS]` | **"No signup, no API key."** Indexes non-GitHub forges that Google and grep.app miss. OpenAPI at `/openapi.json`. |
| [GrayHatWarfare Git](https://git.grayhatwarfare.com) | `[KEY]`, freemium | **The 2026 change to know** — a third GHW product: pre-indexed leaked secrets in public git, searchable **by email domain**. |
| [GrayHatWarfare Buckets](https://buckets.grayhatwarfare.com) | freemium, unauth search works | 18.1bn indexed files across S3/Azure/GCS/DO/Alibaba. Not paywalled shut — capped (500 results unauth, 2k free-registered, ~$25/mo unlimited). |
| [GrayHatWarfare Shorteners](https://shorteners.grayhatwarfare.com) | freemium | Brute-forced short links resolving to Drive/Dropbox/OneDrive docs. **Consistently out-performs Drive dorking** for shared internal documents. |
| [publicwww.com](https://publicwww.com) | `[KEY]`, freemium | Find **our** API keys and analytics IDs embedded in *other people's* pages. Free = top 1M sites, signup = top 3M. |
| [Intelligence X](https://intelx.io) | `[KEY]` `[TOUCHY]` | Selector-typed search (email, domain, IP, CIDR, BTC) across leaks/pastes/Tor. **Domain is a first-class selector** — the best remaining domain-wide breach pivot. No free-text search. |
| [GitLab code search](https://gitlab.com/search?scope=blobs) | `[KEY]` | Blob search in public projects; signed-out search redirects to login. |
| [unpkg](https://unpkg.com) / [jsDelivr](https://cdn.jsdelivr.net) | `[KEYLESS]` | Browse the full published contents of any npm package — fastest way to confirm an internal package shipped a secret. |
| [Source Map Visualization](https://evanw.github.io/source-map-visualization/) | free, **client-side only** | Drag-drop a `.js` + `.map` and read original sources. **Nothing is uploaded** — the safe choice. Prefer it over any server-side sourcemap viewer. |

**Paste hunting has no free API any more.** psbdmp.ws is dead and Pastebin's scraping API is PRO-only, so this is now a dork, not a source: `site:pastebin.com`, `site:rentry.co`, `site:paste.ee`, `site:controlc.com`, `site:justpaste.it`, `site:0bin.net` + the domain. `candor.py` says so in its report rather than pretending it checked.

## 8. Search engines & dorking

| Site | Access | Good for |
|---|---|---|
| [Yandex](https://yandex.com/search) | free, `[KEY]` paid API | **Best remaining `filetype:` and `inurl:` fidelity**; indexes documents Google drops. Captchas hard from datacenter IPs. |
| [SearXNG](https://searx.space) | `[KEYLESS]` (`&format=json` where enabled) | Aggregates many engines, self-hostable with JSON output. **The one durable answer to every search-API shutdown below** — self-host an instance for volume dorking. |
| [Brave Search](https://search.brave.com) | `[KEY]`, free 1 q/s | Independent index. The most viable paid-API replacement for the dead Bing API. |
| [DuckDuckGo HTML](https://html.duckduckgo.com/html/?q=) | `[KEYLESS]` | No-JS endpoint that parses without a browser. Weak `site:`/`filetype:` fidelity, rate-limited. |
| [Startpage](https://startpage.com) | `[BROWSER]` | Google results without Google's personalisation or bot-blocking. |
| [Marginalia](https://search.marginalia.nu) | free | Finds forgotten, non-commercial and old pages the majors dropped — occasionally surfaces stale internal docs. |
| [Exploit-DB GHDB](https://www.exploit-db.com/google-hacking-database) | free | Curated dork corpus to seed sweeps. Flaky (502 during checks) — mirror the dorks you rely on. |
| [Google Programmable Search](https://programmablesearchengine.google.com) | `[AUTO]` `[KEY]` | **Sunsetting: the Custom Search JSON API closes 2027-01-01 and is already closed to new signups.** Our existing key keeps working until then; `candor.py`'s Google-dork stage has a finite life. Do not build anything new on it. |
| ~~Bing Search API~~ | **DEAD** | Retired 2025-08-11, all instances decommissioned. Web UI only. |

## 9. Vulnerability intelligence — CPE-exact, not keyword

Keyword CVE matching is how false findings get written. Only two sources were *live-proven* to do version-exact CPE matching:

| Site | Access | Good for |
|---|---|---|
| [NVD](https://nvd.nist.gov) `services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:...` | `[KEYLESS]` (key lifts 5→50 req/30s) | **Exact CPE 2.3 matching** plus full CVSS/CWE/CPE applicability. Authoritative. Caveat: the enrichment backlog means some new CVEs have no CPE rows — **absence of a CPE row is not absence of exposure**. |
| [Shodan CVEDB](https://cvedb.shodan.io/cve/CVE-2021-44228) | `[KEYLESS]` | **No key, no login, exact `cpe23` lookup**, and it returns EPSS + `kev: true` + a proposed action in one call. Best-kept secret for automation. *Correction to our research: the "truncated CPE silently returns nothing" trap did not reproduce — a prefix CPE returned the same CVEs as the full 13-field string. Still pass the full CPE.* |
| [CVE.org](https://www.cve.org) `cveawg.mitre.org/api/cve/CVE-...` | `[KEYLESS]` | The CNA's own record, live before NVD finishes analysis. Use when NVD says "Awaiting Analysis". |
| [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) | `[KEYLESS]` | The whole corpus as JSON for offline grep — better than rate-limited API calls. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `[KEYLESS]` JSON feed | **"Is it actually being exploited"** — the highest-signal prioritisation list. No CPE. Deliberately conservative, so absence ≠ not exploited. |
| [EPSS (FIRST)](https://api.first.org/data/v1/epss?cve=CVE-2021-44228) | `[KEYLESS]` | Probability of exploitation in 30 days — the best de-noiser for a long CVE list. Updates daily, so **record the score date or the number is unreproducible**. |
| [VulnCheck KEV](https://vulncheck.com) | `[KEY]`, free community | A much larger exploited-set than CISA KEV, often weeks earlier. Say *which* KEV you mean in a report. |
| [OSV.dev](https://osv.dev) `api.osv.dev/v1/query` | `[KEYLESS]` | Package+version-exact matching for OSS deps — the right instrument for a lockfile. Batch endpoint available. Doesn't cover OS packages like a distro feed. |
| [GitHub Advisory DB](https://github.com/advisories) `api.github.com/advisories` | `[KEYLESS]` | Authoritative for npm/PyPI/Maven/Go ranges. |
| [ENISA EUVD](https://euvd.enisa.europa.eu) | `[KEYLESS]` | EU register, cross-references CVE/GHSA + exploited status. Useful second opinion when NVD lags. |
| [endoflife.date](https://endoflife.date) `/api/v1/products/{p}` | `[KEYLESS]` | **Is this version supported at all** — the fastest way to turn a version banner into a finding. Verify against the vendor page before putting an EOL date in a report. |
| [opencve.io](https://app.opencve.io) | `[KEY]`, self-hostable | **Subscribe to a vendor/product and get diffs when a CVE changes.** Its tree is CPE-derived, so far less noisy than keyword alerting. Self-host for a pentest team. |
| [Vulners](https://vulners.com) | `[KEY]` | One query across NVD + distro advisories + exploits. CPE-aware syntax; hard rate limits. |
| [VulDB](https://vuldb.com) | `[KEY]` `[BROWSER]` | Widest coverage of low-profile/CN vendor bugs. Entries often thin and partly automated — good for discovery, weak as a citation. |
| [cvedetails.com](https://www.cvedetails.com) | `[BROWSER]` | CPE-indexed vendor→product→version browsing. Derived from NVD — cite NVD for the fact, this for navigation. |
| [Snyk DB](https://security.snyk.io) / [Mend](https://www.mend.io/vulnerability-database/) | free browse | Readable OSS advisories with exploit-maturity rating. Vendor-curated; severity sometimes diverges from NVD. |

## 10. Exploit lookup

| Site | Access | Good for |
|---|---|---|
| [Exploit-DB git mirror](https://gitlab.com/exploit-database/exploitdb) | `[KEYLESS]` | **Make this primary and the website secondary** — it is what `searchsploit` consumes, and it was up while the site was 502ing. `files_exploits.csv` carries the CVE mapping. |
| [Exploit-DB](https://www.exploit-db.com) | free | The canonical curated archive. **Was returning 502 on 2026-11-24** (Sucuri edge, origin timeout, twice ~15min apart) — not retired, just down. Re-check before repeating that claim. |
| [Rapid7 DB](https://www.rapid7.com/db/) | free | Fastest "is there a Metasploit module", with reliability rating and module path. |
| [metasploit-framework](https://github.com/rapid7/metasploit-framework) | `[KEYLESS]` | `grep -r CVE-20xx modules/` for a definitive answer including modules too new for the web index. |
| [templates.nuclei.sh](https://templates.nuclei.sh) | `[KEYLESS]` | Search the Nuclei corpus by CVE/tag to get a **ready, safe detection**. The best bridge from "CVE exists" to "I can test for it". |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | `[KEYLESS]` | Grep it as a *reference*: it tells you a technology's known exposed paths and fingerprints. |
| [trickest/cve](https://github.com/trickest/cve) | `[KEYLESS]` | CVE → public PoC index, continuously generated. Complements nuclei-templates (detection) with exploitation. |
| [Sploitus](https://sploitus.com) | free | One box across EDB + GitHub PoCs + Packet Storm + Vulners. Great recall, **zero curation** — read every hit. |
| [Packet Storm](https://packetstorm.news) | free | Long-tail advisories not in EDB. **Rebranded — `packetstormsecurity.com` now redirects to `packetstorm.news`.** |
| [AttackerKB](https://attackerkb.com) | free browse | Practitioner assessments of **how exploitable a bug really is** — ideal for justifying a severity call against a CVSS-9 nobody can exploit. |
| [CXSecurity](https://cxsecurity.com/wlb/) | free | Older/obscure web-app exploits. Archival; low curation. |

## 11. Technology, TLS & header posture

| Site | Access | Good for |
|---|---|---|
| [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory) | `[KEYLESS]` v2 API | **The best scriptable header grader available** — `POST observatory-api.mdn.mozilla.net/api/v2/scan?host=`. Supersedes `observatory.mozilla.org`; the old v1 API and TLS/SSH observatory scanners are gone. |
| [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) | `[KEYLESS]` v3, `[KEY]` v4 | The reference TLS grade. v3 `/api/v3/analyze` still works unauthenticated; v4 requires an email header. **Results are public by default — set `publish=off`.** Grading criteria changed in 2025, so state the grading date. |
| [CryptCheck](https://cryptcheck.fr) | `[KEYLESS]` (append `.json`) | Stricter cipher-level grading than SSL Labs, incl. SMTP/IMAP/XMPP. Strong second opinion. |
| [Hardenize](https://www.hardenize.com) | free report | **One page covering TLS + DNS + DNSSEC + CAA + SPF/DKIM/DMARC/MTA-STS together.** Still free post-Red-Sift acquisition. Best single-shot whole-posture page. |
| [internet.nl](https://internet.nl/) | free | Authoritative scored test of IPv6, DNSSEC, TLS, DANE and mail security. Dutch-government-backed, shareable permalinks — good client-facing evidence. |
| [securityheaders.com](https://securityheaders.com) | `[BROWSER]` | De-facto standard header grade. **Grades presence, not quality — an A can still have a bypassable CSP.** Use `&hide=on`. |
| [Netcraft Site Report](https://sitereport.netcraft.com) | free, no account | **Hosting history, netblock/ASN lineage, uptime and tech** — best single page for "who actually hosts this, and since when". |
| [retire.js](https://retirejs.github.io/retire.js/) | `[KEYLESS]` vuln JSON | Flags vulnerable JS libraries by fingerprint. **A renamed or bundled library evades it** — same blind spot as our own bundle scanner. |
| [WhatCMS.org](https://whatcms.org) | `[KEY]` | Narrow but accurate CMS **plus version** detection. |
| [BuiltWith](https://builtwith.com) / [W3Techs](https://w3techs.com) | freemium | Tech timeline; prevalence statistics. Cite W3Techs for "how common is this", not for fingerprinting. |
| [Wappalyzer](https://www.wappalyzer.com/lookup/) | `[KEY]` | **Now a lead-gen/enrichment product** — the free anonymous one-off lookup is effectively gone; the extension still works. |
| [ImmuniWeb Community](https://www.immuniweb.com/websec/) | free, quota | TLS + headers report. **Results public by default**; the compliance verdicts ("PCI FAIL") are sales copy — use the raw facts. |
| [Sucuri SiteCheck](https://sitecheck.sucuri.net) | free | "Is this lookalike actively serving malware". Remote signatures only — a clean result proves little. |
| [URLVoid](https://www.urlvoid.com) | free web | 30+ blocklist verdicts at once. Name the engine that flagged it. |

### Microsoft 365 / Entra tenant recon — all keyless, all from Microsoft itself

| Endpoint | Good for |
|---|---|
| [`login.microsoftonline.com/getuserrealm.srf?login=user@domain&xml=1`](https://login.microsoftonline.com/getuserrealm.srf) `[KEYLESS]` | Managed vs federated vs unknown, **plus the federation endpoint naming the IdP**. Also a tenant-existence oracle. Our SAML/IdP-confusion lead starts here. |
| `login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration` `[KEYLESS]` | Domain → **tenant GUID** in one GET. The cleanest primitive, with no third party in the loop. |
| [AADInternals OSINT](https://aadinternals.com/osint/) | Tenant ID, brand name, verified domains, desktop-SSO state, CBA/MFA hints — the best single web tool for Entra recon. Pair with `Invoke-AADIntReconAsOutsider` for repeatable output. |
| `autodiscover-s.outlook.com/autodiscover/autodiscover.json/v1.0/user@domain?Protocol=Autodiscoverv1` `[KEYLESS]` | Exchange Online vs on-prem/hybrid without auth. Also probe `autodiscover.<domain>` for a stray on-prem endpoint — a classic hybrid finding. |
| [Remote Connectivity Analyzer](https://testconnectivity.microsoft.com) | Vendor-grade external diagnostics. **Use only the unauthenticated tests** — the credentialed ones want a real mailbox password. |
| [Google CheckMX](https://toolbox.googleapps.com/apps/checkmx/) | Workspace detection + SPF/DKIM/DMARC/MX verdicts. Fastest "Microsoft or Google" call. |

### Typosquat & brand

| Site | Access | Good for |
|---|---|---|
| [dnstwister](https://dnstwister.report) | `[KEYLESS]` JSON + email alerts | The scriptable hosted answer to dnstwist. Small operator — don't build a client SLA on it. |
| [dnstwist hosted](https://dnstwist.it) | free | Canonical engine with resolution/MX/banner enrichment. Use the CLI (`--registered --mx --phash`) for an engagement. |
| [Have I Been Squatted](https://haveibeensquatted.com) | `[KEY]` | Quick check with client-friendly screenshots. Detection depth below dnstwist + crt.sh. |

> No hosted `urlcrazy` or `cloud_enum` exists. Results claiming otherwise are impostor sites that harvest the names you type. Run those locally.

## 12. People, email & credential exposure `[TOUCHY]`

**Get this whole section into the RoE before using it.** Stolen-credential queries and biometric search against named employees carry real GDPR / KSA-PDPL exposure even inside an authorised engagement.

`[D]` = enumerates from a company domain (what actually maps a phishing surface). `[R]` = resolve-only, needs an identity you already hold.

### The `[D]` chain that works

1. [email-format.com](https://www.email-format.com) — free, no account, pure **naming-pattern oracle** for 25M+ domains. Gives you `{first}.{last}@` before you spend a credit anywhere.
2. [CrossLinked](https://github.com/m8sec/CrossLinked) — free OSS, scrapes search engines for LinkedIn employee names, then mints addresses from a format string. **No LinkedIn creds, no API key** — the cleanest no-auth org→namelist tool.
3. [Hunter.io](https://hunter.io) `[KEY]` — Domain Search returns known addresses + confidence + pattern. / [Apollo.io](https://www.apollo.io) `[KEY]` — **API access on the free plan**, unusual and useful.
4. [XposedOrNot](https://xposedornot.com) `[KEYLESS]` — free, no-login, open-source **domain** breach check; the closest free substitute for HIBP domain search. / [Hudson Rock Cavalier](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) — **infostealer-infected machines** by corporate domain, free core tools. Highest-signal source for live phishing-surface risk.

### Other entries

| Site | Access | Notes |
|---|---|---|
| [Have I Been Pwned](https://haveibeenpwned.com) | `[KEY]`; Pwned Passwords + breach catalogue `[KEYLESS]` | The only source citable in a client report without argument. **Domain search requires proving domain ownership** — perfect for our own estate, useless against a target we don't own. |
| [Intelligence X](https://intelx.io) | `[KEY]` | Domain is a first-class selector. See §7. |
| [LeakCheck](https://leakcheck.io) | `[KEY]` | Free tier names the breach source only. Domain search supported; *reverse* domain search is Enterprise. |
| [DeHashed](https://dehashed.com) | `[KEY]`, ~$0.02/query | Cheap per-query credential search. `[R]` mostly. |
| [Snusbase](https://snusbase.com) | `[KEY]`, ~$30/mo | **Correction to our research: this resolves fine (Cloudflare) — it was bot-blocking the scraper, not dead.** Historically the best wildcard/domain breach pivot. |
| [BreachDirectory](https://breachdirectory.org) | free web / `[KEY]` | Quick triage; depth unverified. |
| [Snov.io](https://snov.io), [Prospeo](https://prospeo.io), [Skrapp](https://skrapp.io), [FindThatLead](https://findthatlead.com), [Lusha](https://www.lusha.com), [RocketReach](https://rocketreach.co), [ContactOut](https://contactout.com) | `[KEY]` | `[D]` commercial address discovery. Lusha has a permanent free 40 credits/mo; ContactOut is weak without LinkedIn in the loop. |
| [VoilaNorbert](https://www.voilanorbert.com) | `[KEY]`, 50 free | Name + company URL → one verified address. |
| [Verifalia](https://verifalia.com) (25/day free), [ZeroBounce](https://www.zerobounce.net) (100/mo), [NeverBounce](https://www.neverbounce.com), [Email Hippo](https://www.emailhippo.com) | `[KEY]` | Verification `[R]`. ZeroBounce's "Email Activity Data" is a soft liveness oracle. |
| [WhatsMyName](https://whatsmyname.app) | `[KEYLESS]` data file | The community site list everything else borrows (`wmn-data.json`). |
| [Namechk](https://namechk.com), [Instant Username Search](https://instantusername.com), [KnowEm](https://www.knowem.com.au) | free | Username enumeration `[R]`. **`knowem.com` SERVFAILs — only the `.com.au` property answers.** "Taken" ≠ "that person". |
| [Sherlock](https://github.com/sherlock-project/sherlock), [Blackbird](https://github.com/antoniaci/blackbird) | free OSS | 400+/600+ platforms, CLI only. **No official hosted version — treat any "Sherlock online" site as hostile input logging.** Blackbird moved from `p1ngul1n0/` to `antoniaci/`. |
| [holehe](https://github.com/megadose/holehe) | free OSS | Which sites an email is registered on, via forgot-password oracles. **Unmaintained since 2024-09** — many modules stale. |
| [Epieos](https://epieos.com), [Predicta Search](https://www.predictasearch.com), [OSINT Industries](https://osint.industries) | freemium/`[KEY]` | `[R]` email/phone resolvers. Epieos's Google-account pivot and Predicta's **account-creation timestamps** are the unique bits. |
| [GHunt](https://github.com/mxrch/GHunt) | free OSS | Gmail → Google ID, profile, Maps contributions. **Requires your own authenticated Google cookies — your account takes the risk.** |
| [IDCrawl](https://www.idcrawl.com), [ThatsThem](https://thatsthem.com), [TruePeopleSearch](https://www.truepeoplesearch.com), [FastPeopleSearch](https://www.fastpeoplesearch.com), [Spokeo](https://www.spokeo.com) | free/freemium | US people-search `[R]` `[TOUCHY]`. The relatives+neighbours graph is the pretexting goldmine and the reason to think twice. Bad optics in an EU/GCC-facing document. |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), [NumLookup](https://www.numlookup.com) | OSS / free | Phone `[R]`. NumLookup's **line-type** (mobile/landline/VoIP) is the useful bit for SMS-phishing feasibility. PhoneInfoga is self-declared "stable but unmaintained". |
| [PimEyes](https://pimeyes.com), [FaceCheck.ID](https://facecheck.id) | freemium `[TOUCHY]` | **Riskiest category here.** Biometric processing; PimEyes' own ToS frames it as searching your *own* face. Hard to defend against named employees. |
| [Maltego](https://www.maltego.com/pricing/) | free CE + paid | **Community Edition still exists** as the "Basic" plan, desktop and browser. Paid tiers €3,000/€7,500 per year. |
| [Social Links](https://sociallinks.io), [Skopenow](https://www.skopenow.com) | paid | Strongest social-graph coverage; buyer-vetting and procurement cycles. |

## 13. Document, file & SaaS exposure

| Site | Access | Good for |
|---|---|---|
| [DocumentCloud](https://www.documentcloud.org) | `[KEYLESS]` API | OCR'd full text of journalist/FOIA document corpora. **The SPA 403s automation — use `api.www.documentcloud.org/api/documents/search/?q=`.** |
| [SlideShare](https://www.slideshare.net/search) | free | Internal decks — architecture diagrams, vendor lists, roadmaps. **Chronically under-used; decks leak more than documents do.** |
| [Scribd](https://www.scribd.com/search) | freemium | Accidentally-public internal docs. `site:scribd.com` on Google beats its own search. |
| [OSINT.sh buckets](https://osint.sh/buckets) | free | Keyword search of S3 **and** Azure Blob in one box. Browser only. |
| [npm registry search](https://registry.npmjs.org/-/v1/search?text=) | `[KEYLESS]` | Accidentally-published internal packages and scope-squats of our name. |
| [Docker Hub search](https://hub.docker.com/v2/search/repositories/?query=) | `[KEYLESS]` | Org images whose layers retain build-time tokens. **Finding the image is step one — the leak is almost always in a non-final layer.** |
| [PyPI](https://pypi.org/search/) | web only | Legacy XML-RPC search is disabled; JSON API is per-package. |
| Trello / Jira / Confluence / Drive | dorks only | Trello search is login-walled. Use `site:trello.com/b "<org>"`, `site:atlassian.net "<org>"`, `inurl:/wiki/spaces`, then check `/rest/api/latest/*` unauthenticated on tenants we own. |

### Malware sandboxes — read freely, **never submit** `[UPLOADS]`

[ANY.RUN](https://app.any.run/submissions), [Hybrid Analysis](https://hybrid-analysis.com), [Joe Sandbox](https://www.joesandbox.com), [Triage](https://tria.ge), [VirusTotal](https://www.virustotal.com), [MalwareBazaar](https://bazaar.abuse.ch).

Staff upload internal invoices, payslips and VPN configs to these constantly, so **searching them for our own leaked documents is high-yield and safe**. Submitting anything of ours is itself the disclosure we are trying to find — free tiers publish permanently, to every paying customer. VTGrep content search and Retrohunt are Enterprise-only; free VT keys get hash/domain/IP lookups at 4 req/min.

## 14. Methodology & reference

| Resource | State | Good for |
|---|---|---|
| [HackTricks](https://hacktricks.wiki/) | **commits daily** | The encyclopedia: per-port, per-service, per-technology attack pages. **Domain moved** — `book.hacktricks.*` bookmarks should be updated (verified 301). |
| [HackTricks Cloud](https://cloud.hacktricks.wiki/) | active | AWS/GCP/Azure/K8s enumeration and privesc paths by permission. |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | active | Best payload depth per bug class. HackTricks is better per-target; this is better per-vuln. |
| [OWASP WSTG](https://wstg.owasp.org/v4.2/) §4.1 | v4.2 stable (2020), v5 in dev | **The only test-ID'd recon checklist** (WSTG-INFO-01…10). Cite v4.2 IDs for auditability, read `/latest` for current content. |
| [MITRE ATT&CK TA0043](https://attack.mitre.org/tactics/TA0043/) | living, ATT&CK v20 | Blue-team-legible recon language. 2026 additions: T1595.003 Wordlist Scanning, T1682 Query Public AI Services, T1681 Search Threat Vendor Data. |
| [Bugcrowd VRT](https://bugcrowd.com/vulnerability-rating-taxonomy/) | v1.19, Jul 2026 | P1–P5 for ~500 vuln variants. **CVSS gives a score; VRT gives the house rule** — use it to pre-empt triage disputes. |
| [ProjectDiscovery docs](https://docs.projectdiscovery.io/) | updated continuously | **Flags that actually exist in the version you installed** — most recon blog posts use dead flags. |
| [six2dez pentest-book](https://six2dez.gitbook.io/pentest-book) | pushed this month | The closest thing to a *maintained* TBHM: one practitioner's current workflow, in order. |
| [reconFTW](https://github.com/six2dez/reconftw) | active | Read the source as a methodology document — it encodes the 2026 consensus recon order. "Methodology you can diff." |
| [Trickest library](https://trickest.com/library) | 144 workflows | Published pipelines (origin-IP-behind-Cloudflare, Wayback secrets, SPA endpoint mapping). Read the node graph to steal the tool ordering without an account. |
| [Bellingcat Toolkit](https://bellingcat.gitbook.io/toolkit) | monthly, per-page maintainers | **The only big directory with an explicit maintenance commitment.** Best for *whether a tool still works*. Weak on offensive infra. |
| [Awesome-OSINT](https://github.com/jivoi/awesome-osint) | pushed 2026-11 | Git-tracked, so you can `git log` a link's provenance — the auditable alternative to osintframework.com. |
| [cipher387/osint_stuff_tool_collection](https://github.com/cipher387/osint_stuff_tool_collection) | near-daily adds | **Highest novelty rate** — where to look when the mainstream tool for a pivot has died. |
| [OSINT Framework](https://osintframework.com/) | maintained but **rotten** | Good at *naming the pivot you forgot exists*, bad at taking you there — it still points at Scylla and Castrick Clues, both dead. Treat every link as unverified. |
| [IntelTechniques Tools](https://inteltechniques.com/tools/) | Aug 2026 | Query-builder pages that fire dozens of lookups per entity. Honest about its own rot ("some tools are currently non-functional"). |
| [start.me — Bruno Mortier INT/Infra](https://start.me/p/V0PXgr/int-infra) | live | The infrastructure/technical-recon board — the one a pentester wants. `noindex`, so bookmark it. |
| [GTFOBins](https://gtfobins.org/) / [LOLBAS](https://lolbas-project.github.io/) | active | Post-foothold binaries. **GTFOBins moved to `gtfobins.org`** (verified 301 from github.io) — update any hardcoded host. LOLBAS carries ATT&CK IDs per entry. |
| [SecLists](https://github.com/danielmiessler/SecLists) | daily | The baseline wordlist collection. `candor.py` pulls `common.txt` from here. |
| [Assetnote wordlists](https://wordlists.assetnote.io/) | mature, quiet 9mo | **Best signal-to-noise per request** — pick the list for the stack you fingerprinted instead of brute-forcing raft. |
| [jhaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) | 2026-10 | The merged-and-deduped fuzzing list. **His gists are current even though `jhaddix/tbhm` is frozen at 2023** — two gists are both named all.txt; the 2026-10-30 one is newer. |
| [trickest/wordlists](https://github.com/trickest/wordlists) | 2026-10 | Derived from internet-wide scan data rather than hand-curated — best complement to SecLists. |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | continuous | Best explanations of each bug class, with labs that prove you understood it. **Often better to link a client here than to HackTricks.** |
| [HackerOne Hacktivity](https://hackerone.com/hacktivity) | live | The only source showing **what triage actually accepted and paid** — calibrate severity and report writing. |
| [Trace Labs OSINT VM](https://github.com/tracelabs/tlosint-vm/releases) | release 2026.10 | Prebuilt OSINT workstation. **2026.05 moved off Kali to Debian 13 and deliberately removed exploit kits and port scanners** — pure collection box now, don't expect offensive tooling. |
| [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) | 2008, Final | Stale and pre-cloud, but often the only citation compliance language accepts. |
| [OSSTMM 3](https://www.isecom.org/OSSTMM.3.pdf) | 2010 | The only standard here that outputs a **quantified** attack-surface metric (RAV). v4 has been "in draft" for a decade. |

## 15. Dead / removed — recognise these in old guides

Every one of these still appears in current "awesome" lists, 2026 blog posts, or default `subfinder`/`amass` configs. They waste time or, worse, return silence that reads like a clean result.

| Gone | What happened |
|---|---|
| **api.bgpview.io / bgpview.io** | **NXDOMAIN, shut down ~2025-11-26.** Broke pfBlockerNG ASN filtering and MISP warninglists. **Was in `candor.py` — replaced with RIPEstat.** |
| **psbdmp.ws** | No A record, no HTTP response. **Was in `candor.py` — removed.** |
| **jldc.me / Anubis-DB** | 301s to `jonlu.ca`, serves HTML not JSON. Still in many subfinder configs. **Was in `candor.py` — replaced with api.subdomain.center.** |
| **BinaryEdge** | Shut 2025-03-31 after the Coalition acquisition; all subscriptions terminated. Highest-profile casualty — strip from amass/subfinder configs. |
| **ThreatCrowd** | No DNS, no HTTP. Cert expired Jan 2025, never renewed; Cortex XSOAR deprecated the integration June 2025. |
| **PassiveTotal / RiskIQ Community** | Hostname doesn't resolve. Absorbed into Microsoft Defender TI / EASM; standalone API retired. |
| **bufferover.run / tls.bufferover.run** | Resolves (CloudFront) but 403s everything. subfinder's own tracker calls it "effectively dead for free users". |
| **ThreatMiner** | Cloudflare 522, origin unreachable. |
| **SpyOnWeb** | DNS resolves to a stale IP; no HTTP on 80 or 443. Use DNSlytics or BuiltWith Relationships. |
| **Shrewdeye** | No DNS, no HTTP. |
| **DNSGrep** | `.io` NXDOMAIN; `.cn` 403 to everything. |
| **Entrust CT Search** | No HTTP response at all. |
| **Facebook CT Monitoring** | 404. Retired by Meta. |
| **cs.github.com** | CNAME → `redirect.github.com`. Folded into `github.com/search`. |
| **shhgit.com** | Now a generic SEO content blog; upstream repo archived. The live-firehose UI is gone. |
| **FilePursuit** | NXDOMAIN. Its RapidAPI listing is stale and will fail. |
| **SearchFTPs** | Resolves behind Cloudflare but 403s; no usable output. |
| **Memento Time Travel** | NXDOMAIN. The 20-archive aggregator is gone — query archives individually. |
| **Clearbit** | **`clearbit.com` is NXDOMAIN.** Free tools ended 2025-04-30, Logo API shut 2025-12-08, absorbed into HubSpot Breeze. |
| **Scylla.sh** | Resolves to a domain-parking page (`abovedomains` nameservers). |
| **Castrick Clues** | Nameservers set, **no A record** — site down. Still listed in several awesome-* repos. |
| **Qualys FreeScan** | Retired 2019, EOL'd 2021, host no longer connects. |
| **PTES (pentest-standard.org)** | **DNS resolves but HTTP times out on both :80 and :443** — verified from two vantage points. Concept survives only in third-party copies and Wayback. Don't cite the link. |
| **MITRE PRE-ATT&CK** | Retired Oct 2020 into TA0043 + TA0042. Any 2026 doc citing it is copying a stale source — a useful currency smell test. |
| **0day.today** | **Domain repurposed as a Latvian online-casino SEO site.** No exploit content. Don't visit from a work host. |
| **Bing Search API** | Retired 2025-08-11, all instances decommissioned. |
| **Google cache / `cache:` dorks** | Retired 2024. CachedView is now just a Wayback form. |
| **Truecaller web search** | `/search/us` 404s — identification is app-only now. |
| **Pipl public search** | Repositioned to enterprise fraud intelligence; no free people search. |
| **Phonebook.cz** | Now requires paid IntelX SSO. No longer the free domain-dump old guides describe. |
| **Pentester Land** | Last writeups Sep 2024, last post Jan 2023. Fine as a 2015–2024 archive, not current awareness. |
| **jhaddix/tbhm**, **Nahamsec resources**, **EdOverflow cheatsheet**, **fuzzdb** | Abandoned 2023–2024. Still useful as archives; the maintained TBHM is now the paid Arcanum course. |

## 16. Newly gated — alive, but no longer scriptable without a key

`chaos.projectdiscovery.io` · `DNSDumpster` API (401) · **Censys search API — free accounts cannot call it at all** · `SecurityTrails` API (401, free subdomain enum gone) · `ipdata.co` (401) · `AbuseIPDB` (401) · `WiGLE` (401) · `ViewDNS` tools + API (403/401 to scripts) · `abuse.ch` family (URLhaus/MalwareBazaar/ThreatFox now need a free Auth-Key) · `GitHub` + `GitLab` code search (login) · `Trello` search (login) · `Wappalyzer` lookup · `Shodan` filters.

## 17. The keyless shortlist — scriptable today, no account

All verified returning real data to an unauthenticated request on 2026-11-24:

```
crt.sh/?q=%25.DOMAIN&output=json              # CT (slow, 502s; use 60s timeout)
api.certspotter.com/v1/issuances              # CT (~100/hr/IP)
api.subdomain.center/?domain=DOMAIN           # independent crawl  <-- best yield for us
api.hackertarget.com/hostsearch/?q=DOMAIN     # quota error arrives as text in a 200
rapiddns.io/subdomain/DOMAIN?full=1           # HTML only
urlscan.io/api/v1/search/?q=domain:DOMAIN     # others' scans
web.archive.org/cdx/search/cdx?url=*.DOMAIN/* # every historical URL
index.commoncrawl.org/CC-MAIN-YYYY-WW-index   # paths Wayback missed
archive.org/advancedsearch.php?output=json    # item metadata, different corpus
rdap.org/domain/DOMAIN                        # WHOIS as JSON (302, follow it)
rdap.verisign.com/com/v1/domain/DOMAIN        # .com/.net direct
stat.ripe.net/data/network-info/data.json     # IP -> ASN + prefix
stat.ripe.net/data/as-overview/data.json      # ASN -> holder
bgp.tools/table.jsonl                         # needs a descriptive User-Agent
internetdb.shodan.io/IP                       # ports + CPEs + CVEs per IP, no credits
api.greynoise.io/v3/community/IP              # scanner noise vs real
ipinfo.io/IP/json                             # geo + org + anycast (~1k/day)
freeapi.robtex.com/ipquery/IP                 # reverse DNS + BGP (NDJSON)
dns.google/resolve?name=DOMAIN&type=A         # DoH JSON; bypasses local resolver
cvedb.shodan.io/cves?cpe23=FULL_CPE           # exact-CPE CVEs + EPSS + KEV
services.nvd.nist.gov/rest/json/cves/2.0?cpeName=  # authoritative exact CPE
api.first.org/data/v1/epss?cve=CVE-...        # exploitation probability
cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
api.osv.dev/v1/query                          # package+version exact
api.github.com/advisories                     # GHSA
endoflife.date/api/v1/products/PRODUCT        # is this version even supported
observatory-api.mdn.mozilla.net/api/v2/scan?host=  # header grade (POST)
ssllabs.com/api/v3/analyze?host=              # TLS grade (v3 keyless, v4 is not)
cryptcheck.fr/https/DOMAIN.json               # stricter TLS second opinion
login.microsoftonline.com/getuserrealm.srf?login=u@DOMAIN&xml=1
login.microsoftonline.com/DOMAIN/v2.0/.well-known/openid-configuration
searchcode.com api.searchcode.com/api/v1/     # code search, no signup
grep.app/api/search?q=                        # code search (429s hard)
```

`[AUTO]` ones are already in `candor.py`. The rest are candidates to wire in — `cvedb.shodan.io` + `endoflife.date` would turn its version banners into CVE findings, and the MDN Observatory API would replace its hand-rolled header check.

---

### Verification caveats

Status was established by DNS resolution, HTTP status, published "last updated" strings and GitHub `pushed_at` on **2026-11-24**. No accounts were created, so free-tier **quotas** come from vendors' own pricing pages rather than observed behaviour, and those numbers drift monthly.

Several `403`/`429` verdicts are Cloudflare bot-blocks from an automated client, not outages — those sites work in a browser, which is how a pentester uses them, but it means they cannot be scripted from our automation hosts without a key. Three initial "dead" calls were **wrong for exactly this reason** and were corrected after re-checking from here: Snusbase resolves fine, and the claim that a truncated CPE makes `cvedb.shodan.io` silently return nothing did not reproduce. Exploit-DB's 502 may well have cleared by the time you read this.
