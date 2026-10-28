# Contributing

Bug reports and pull requests are welcome. For a larger change, open an issue first so we can agree on the approach.

## Development

You need Go (the version in `go.mod`), a C compiler (the 1Password SDK's desktop integration uses CGO) and `sops` on `PATH`.

```bash
go build ./...
go test ./...
gofmt -l . && go vet ./... && go tool staticcheck ./...
```

The tests never reach a real 1Password account. They run against an in-memory backend (`internal/onepassword/optest`) and vaults in temporary directories. Without `sops` the open-vault tests are skipped; CI sets `TANDEMVAULT_REQUIRE_SOPS=1` so they fail there instead.

`scripts/package.sh VERSION ARCH OUTDIR` builds the tarball, `.deb`, `.rpm` and Arch package the way a release does. It needs [nfpm](https://nfpm.goreleaser.com/) and builds for the machine's own architecture only.

## Layout

- `cmd/tandemvault`: entry point.
- `internal/cli`: argument parsing and the commands.
- `internal/engine`: planning and applying a sync.
- `internal/vault`: the `sops-dotenv` and `age-dir` formats.
- `internal/onepassword`: the SDK and CLI backends.
- `internal/mapping`: `mappings.yaml` and `state.json`.
- `internal/otp`: one-time password parsing and comparison.

## Rules that keep values safe

- No value in a plan line, log message, error or file other than a vault. Build output from names. The tests assert this with marked values; keep new tests doing the same.
- Values reach other programs over stdin or pipes, never as arguments.
- 1Password is written before the vault, and only through `Backend.Update`, which checks the item version.

## Pull requests

- Add a line under `[Unreleased]` in `CHANGELOG.md` for anything a user notices.
- Update the README or `docs/` when behaviour or configuration changes.
- CI (the `Validation` check) has to pass. `main` takes rebase merges only.

## Releases

A release is a tag `vX.Y.Z` on a commit of `main` whose CI passed, after a pull request that moves `[Unreleased]` into a dated `[X.Y.Z]` section. The tag starts `.github/workflows/release.yaml`, which tests, builds on native amd64 and arm64 runners, writes `checksums.txt`, attests the files and publishes the GitHub release with that changelog section as its notes.
