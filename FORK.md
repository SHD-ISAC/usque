# Personal MASQUE build

`masque-hardening` is based on upstream **v4.2.1**
(`6aa03fc97d12848dce34eedbd187fb1077b5d1ea`). The `main` branch is kept at
its original upstream commit.

Included upstream pull requests, reviewed and merged at these exact revisions:

| Pull request | Purpose | Head commit |
| --- | --- | --- |
| [#136](https://github.com/Diniboy1123/usque/pull/136) | Config receiver semantics and private config file permissions | `7ed785d58151725204be5fbb69f60153ed00315d` |
| [#139](https://github.com/Diniboy1123/usque/pull/139) | 30-second Cloudflare API request timeout | `858ec8b7c7f6b38d89bc8b0cb72eaad3eede2b17` |

These patches were still open upstream when imported on 2026-10-21. Review of
these small diffs is not a full security audit of Usque or its dependencies.
The API timeout affects registration and account/device requests, not the
lifetime of the MASQUE tunnel.

## Build

`.github/workflows/build-cachyos.yml` builds the selected `masque-hardening`
commit for Linux amd64 using the Go version declared in `go.mod` (currently
1.26.3). It verifies the selected commit and patch ancestry, downloads and
verifies modules, runs tests and vet, and builds with CGO disabled and
`-trimpath`. Actions are pinned to full commit SHAs and the job has only
`contents: read` permission. It does not publish a GitHub Release.

Pushes to `masque-hardening` trigger the build. Enable GitHub Actions for this
fork first if GitHub displays an enable-workflows prompt.

The workflow also supports `workflow_dispatch`. For the **Run workflow** button
on GitHub, the workflow must be on the default branch. To keep `main` unchanged
and use that button, change the fork's default branch to `masque-hardening` in
repository Settings > General > Default branch. This does not change the
contents of `main`. Until then, use the push-triggered build.

Download the `usque-linux-amd64-<commit>` artifact from a successful run. It
contains the tarball, its SHA-256 checksum, `source-commit.txt`, and
`build-info.txt`. Artifacts are retained for 14 days. The tarball also contains
the source commit, Go build information, and license. The binary's `version`
command includes the full commit; its build date is the source commit date.
Compare the source commit with the commit shown on the workflow run.

After extracting the artifact ZIP into a directory under `~/Downloads`, run
the following from that directory (Fish compatible):

```fish
sha256sum -c usque-linux-amd64.tar.gz.sha256
mkdir -p usque-build
tar -xzf usque-linux-amd64.tar.gz -C usque-build
./usque-build/usque version
cat source-commit.txt
sudo install -m 0755 usque-build/usque /usr/local/bin/usque
```

## Local configuration

Register and test locally after installing the binary. Do not commit Team JWTs,
private keys, access tokens, or real configuration files to this repository.
Use a private configuration directory (0700) and configuration file (0600),
retain endpoint public-key pinning, and do not use `--insecure`.

This build does not install a service, configure routes or DNS, or remove the
official WARP client. `nativetun` requires a separate routing/DNS plan, including
endpoint bypass and coordination with any existing Xray TUN. Keep the official
client available until local Team registration and network tests succeed.
