# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-28

### Added

- Leases: `link --lease` pulls an item for one job, `return` gives it back. Unchanged entries are deleted at once without 1Password; changed ones are written back by the next sync, which checks 1Password holds them before it deletes the vault copy.
- `unlink --keep none` retires an item: write back, check, 1Password item to Recently Deleted, vault entries deleted.
- Link lookup falls back to titles containing the search; the plan names the chosen item and says when it was a best match.
- `vault verify NAME` compares a value on stdin with an entry and prints only `match` or `differs`.
- `status --local` lists leases not returned yet.

## [0.1.1] - 2026-10-28

### Fixed

- The `.rpm` and Arch packages of a release are listed in `checksums.txt` and carry a build provenance attestation, like the `.deb` and the tarballs.

## [0.1.0] - 2026-10-28

### Added

- `sync` with plan, confirmation and `--dry-run`; compare-and-swap before every write; refuses to run while file-sync conflict copies exist.
- `link` (by title or item ID), `link --create` (new 1Password item from vault entries) and `unlink --keep op|vault|both`.
- `vaults` lists 1Password vault IDs; vaults are always referenced by ID.
- `status` and `status --local`, the latter without 1Password or any key.
- `vault init|names|get|set|unset|run` for the `sops-dotenv` and `age-dir` vault formats, with a trash instead of deletion.
- 1Password backends: the Go SDK with desktop app integration (field-level edits that keep passkeys), and the `op` CLI, which edits only items mapped with `passkey: false`.
- One-time password secrets compared by secret and parameters across raw base32 and `otpauth://` forms.
- Release packages for linux amd64 and arm64 (`.deb`, `.rpm`, Arch, tarball) with checksums and build provenance attestations.

[Unreleased]: https://github.com/frederikb96/tandemvault/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/frederikb96/tandemvault/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/frederikb96/tandemvault/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/frederikb96/tandemvault/releases/tag/v0.1.0
