# MASQUE endpoint scout

`usque scout` integrates warpscout-derived MASQUE endpoint probing into this
fork. It uses an **existing Usque registration** and its **original endpoint
public-key pin**. The default profile is **Team**, with the SNI
`zt-masque.cloudflareclient.com`; use `--profile consumer` only with a consumer
registration. `main` and the existing proxy/TUN commands are unchanged.

## First scan (Fish)

After installing the new binary, use the original configuration:

```fish
usque -c "$HOME/.config/usque/config.json" scout
```

Defaults: IPv4 endpoints, both transports, two workers, three independent
attempts per target, and 10 seconds for each complete attempt. QUIC checks
ports **443, 500, 1701, 4500, 4443, 8443, 8095**; HTTP/2 checks **TCP 443**.
The built-in Team candidates are `162.159.197.1` and `.2`, plus the matching
in-range addresses from the loaded configuration. `--family both` also checks
`2606:4700:102::1` and `::2`; `--family 6` checks only IPv6 outer endpoints.
This does not change the tunnel's inner IPv4/IPv6 support.

Each attempt authenticates CONNECT-IP using the registered client key, then
fetches `https://speed.cloudflare.com/meta` through an isolated userspace
network stack. DNS also runs inside that tunnel. The HTTPS request uses normal
certificate and hostname validation. A successful handshake by itself is never
reported as a working endpoint. No elevated privileges, OS TUN, route changes,
DNS changes, extra binaries or local Go installation are required.

The default scan can take several minutes when all candidates time out.
Each completed target prints progress. Ctrl+C cancels active connections and
stops scheduling new targets.

## Save a report and a separate selected config

```fish
set usque_scout_run (date +%Y%m%d-%H%M%S)
usque -c "$HOME/.config/usque/config.json" scout \
    --profile team --family both --transport both \
    --output-report "$HOME/Downloads/usque-scout-$usque_scout_run.json" \
    --write-config "$HOME/.config/usque/scout-$usque_scout_run.json"
```

By default the scanner writes nothing. Both output flags are optional; files
are created with mode **0600**, and existing paths or symlinks are refused.
The report contains candidate endpoints, timing, metadata and errors, without
the registration ID, private key, access token or full peer key. Review network
and location information before sharing a report.

The config copy is created **only if a candidate passes both the pinned
CONNECT-IP handshake and the tunneled HTTPS check**. It retains every original
field, including unknown fields and `endpoint_pub_key`, and changes only the
selected transport/family's endpoint IP. It never overwrites the input file.
The copy contains the same sensitive credentials as the original; keep it local.

The command prints a Fish-compatible `socks` test command with the correct
config copy, SNI, port, outer IP family and `--http2` if needed. **Use those
flags**: the config format does not store the selected port, SNI or transport.
The scanner never starts a proxy or replaces the configuration automatically.

## Narrow a diagnostic scan

Only a selected Team endpoint and two QUIC ports:

```fish
usque -c "$HOME/.config/usque/config.json" scout \
    --endpoints 162.159.197.2 --transport quic --ports 443,8443
```

Only HTTP/2, preserving the original pin:

```fish
usque -c "$HOME/.config/usque/config.json" scout --transport http2
```

Specify endpoint IPs with `--endpoints IP,IP,...`; this replaces the default
list. Small CIDRs are supported, with a total cap of 256 unique IPs and 4096
endpoint/transport/port combinations. IPv6 `/48` sweeps are refused. Candidate
IPs must be in the selected profile's published/warpscout MASQUE ranges;
hostnames, private addresses and the other profile's ranges are rejected.
A range is an allowlist, not a promise that each address serves MASQUE.
Team scans exclude Usque's legacy consumer HTTP/2 default `162.159.198.2`.

`--sni-address NAME` overrides SNI without changing the pinned peer key.
`--ports` overrides the port list for **all selected transports**; non-443 TCP
ports are experimental and not part of the documented Team fallback defaults.
`--workers` accepts 1..8, `--attempts` 1..10, and `--timeout` 1s..1m.
`-i 1200` can test a fixed initial QUIC packet size; the default `-i 0` matches
Usque's normal PMTU discovery. The suggested proxy command retains a custom `-i`.

## Reading results

| Result | Meaning |
| --- | --- |
| `ok` | Original pin accepted, CONNECT-IP established, tunneled HTTPS returned valid metadata |
| `pin-mismatch` | Peer key differs from the configured original pin; no automatic trust change |
| `timeout`, stage `connect` | Tunnel setup did not complete within the attempt deadline |
| `timeout`, stage `probe` | CONNECT-IP completed but tunneled DNS/HTTPS did not finish |
| `http-error` | CONNECT-IP or metadata endpoint returned an error status; JSON records the stage and error |
| `auth-error` | Peer rejected the TLS authentication |
| `connect-error` / `probe-error` | Other setup or inner-network failure; consult the report |

Rows are ranked by successful-attempt ratio, then **median end-to-end attempt
time**. `MEDIAN ms` includes connection setup, DNS and HTTPS; it is not ICMP RTT.
`COUNTRY` and `COLO` come from the fastest successful metadata response.
No host ping is used, avoiding false positives from router ping interception.

All endpoint dials ignore environment proxies, so a local HTTP proxy cannot
silently replace the candidate IP. Router-level transparent proxying still
affects the network path. Keep that in mind when comparing Wi-Fi and hotspots.

The scanner cannot manufacture a valid peer pin, refresh Team enrollment, fix
protocol incompatibility or prove an endpoint will stay stable. Metadata can
also be blocked by Team Gateway policy. No working candidate produces an error
exit status, a report if requested, and **no config copy**. It does not trigger
registration or contact a third-party API relay. A successful probe does not
replace separate throughput, long-lived connection, inner IPv4/IPv6 and UDP tests.

## Source and build

Adapted from [vernette/warpscout](https://github.com/vernette/warpscout) commit
`b49ef5e8a466164a64d669951521b58944346bc8`. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the original MIT license.
Only the MASQUE probing portions are adapted; no new Go module dependencies
are added. The Go 1.26.10 workflow runs tests, vet and race checks and includes
this guide and the third-party notice in the binary tarball.
