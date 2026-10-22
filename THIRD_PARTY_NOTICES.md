# warpscout-derived MASQUE endpoint probing

The `scout/` package adapts the MASQUE probing design, endpoint/port lists,
packet forwarding and metadata parsing from
[vernette/warpscout](https://github.com/vernette/warpscout) at commit
`b49ef5e8a466164a64d669951521b58944346bc8` (2026-09-03), especially `masque.go`,
`tunnel.go`, `meta.go` and `workers.go`.

This adaptation adds Team address ranges and SNI, reuses an existing Usque
registration, owns transport resources per attempt, enforces cancellation,
preserves the registered peer pin, and exports only to explicitly requested
new files. It does not include warpscout's registration, account relay,
WireGuard/AmneziaWG or terminal UI. No warpscout module dependency is added.

The Team ranges and default ports are documented by Cloudflare:
https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/

The following notice applies to the adapted warpscout portions. Other source
and dependencies retain their respective licenses, including Usque's LICENSE.md.

## warpscout license

MIT License

Copyright (c) 2026 Nikita S.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
