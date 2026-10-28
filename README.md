<table>
<tr>
<td width="140">
<img src="docs/logo.png" alt="tandemvault" width="120">
</td>
<td>
<h1>tandemvault</h1>
Keeps selected 1Password items in step with SOPS/age vaults on disk.
</td>
</tr>
</table>

[![CI](https://github.com/frederikb96/tandemvault/actions/workflows/ci.yaml/badge.svg)](https://github.com/frederikb96/tandemvault/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/frederikb96/tandemvault)](https://github.com/frederikb96/tandemvault/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

1Password is where you keep the logins you use yourself. Scripts, services and agents on your machine need some of the same credentials, and they need them without a fingerprint prompt every time. tandemvault keeps two kinds of local vault for that, and syncs the items you pick between them and 1Password:

- an **open vault**: a [sops](https://github.com/getsops/sops)-encrypted dotenv file. Anything running as your user with the sops age key can read it.
- a **sealed vault**: one [age](https://age-encryption.org/) file per secret. Adding a secret needs nothing, reading one needs a passphrase, which can itself live in 1Password.

You decide which 1Password items are synced, into which vault, under which names. Only four fields take part: username, password, one-time password (TOTP) and the primary URL. Notes, other fields, files, passkeys and item titles are never touched.

A sync is something you run by hand. It connects to the 1Password app (one approval), shows the plan, asks, and only then writes:

```
$ tandemvault sync
1Password: connected (sdk)
Plan: 3 change(s) in 2 item(s)
  Example Shop [sealed/SHOP]  password       vault → 1Password      (vault changed)
  Forum [open/FORUM]          FORUM_USER     create from 1Password  (missing in vault)
  Forum [open/FORUM]          FORUM_PASSWORD create from 1Password  (missing in vault)
Apply? [y/N]
```

The plan names items, entries and directions. It never shows a value.

## Install

Releases are built on GitHub-hosted runners from a tag. Every release has, for linux amd64 and arm64, a `.deb`, an `.rpm`, an Arch package and a plain tarball, plus a `checksums.txt` and a build provenance attestation that ties each file to the workflow run that built it. The binary needs glibc (any current Debian, Ubuntu, Fedora, RHEL, openSUSE or Arch; not Alpine).

Download the file for your system and check it before installing. With the GitHub CLI:

```bash
VERSION=$(gh release view --repo frederikb96/tandemvault --json tagName --jq .tagName)
FILE="tandemvault_${VERSION#v}_amd64.deb"   # or _amd64.rpm, _amd64.pkg.tar.zst, _linux_amd64.tar.gz; arm64 likewise
gh release download "$VERSION" --repo frederikb96/tandemvault --pattern "$FILE" --pattern checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "$FILE" --repo frederikb96/tandemvault
```

`sha256sum` must print `OK` for the file, and `gh attestation verify` must report a verified attestation from this repository's release workflow. Then install it:

| File | Install | Re-check later |
|---|---|---|
| `.deb` (Debian, Ubuntu) | `sudo apt install "./$FILE"` | `dpkg --verify tandemvault` |
| `.rpm` (Fedora, RHEL, openSUSE) | `sudo dnf install "./$FILE"` or `sudo zypper install "./$FILE"` | `rpm --verify tandemvault` |
| `.pkg.tar.zst` (Arch) | `sudo pacman -U "./$FILE"` | `pacman -Qkk tandemvault` |
| tarball (any glibc distribution) | `tar -xzf "$FILE" && sudo install -o root -g root -m 0755 tandemvault_*/tandemvault /usr/local/bin/` | compare `sha256sum /usr/local/bin/tandemvault` with the extracted binary |

Each way puts the binary somewhere owned by root, so nothing running as your user can swap it. Without the GitHub CLI, download the files from the release page and check the checksum the same way; the attestation check needs `gh`.

tandemvault also needs:

- `sops` 3.9 or newer on `PATH`, for the open vault.
- The 1Password desktop app with SDK integration turned on, for `sync`. See [docs/onepassword.md](docs/onepassword.md). The vault commands and `status --local` work without it.

## Quick start

Create `~/.config/tandemvault/config.yaml`:

```yaml
onepassword:
  account: my.1password.com   # account name from the app's sidebar, or its UUID
vaults:
  open:
    type: sops-dotenv
    path: ~/.local/share/tandemvault/open.env
  sealed:
    type: age-dir
    dir: ~/.local/share/tandemvault/sealed
    passphrase: op://Private/tandemvault sealed vault/password
```

Create both vaults. The open vault is encrypted to your sops age key (`~/.config/sops/age/keys.txt` by default). The sealed vault reads its passphrase from the 1Password item named in the config, so create that item first:

```bash
tandemvault vault init --vault open
tandemvault vault init --vault sealed
```

Link a 1Password item to entries in a vault and sync:

```bash
tandemvault link "Example Shop" --vault sealed --prefix SHOP
tandemvault sync
```

The sealed vault now holds `SHOP_USER`, `SHOP_PASSWORD`, `SHOP_TOTP_SECRET` and `SHOP_URL`, as far as the item has them. Change one on either side and the next sync carries it over.

## Using the vaults

```bash
tandemvault vault names --vault open
printf '%s' "$value" | tandemvault vault set --vault open API_TOKEN   # value on stdin, never as an argument
tandemvault vault run --vault open API_TOKEN -- ./deploy.sh           # API_TOKEN in deploy.sh's environment only
tandemvault vault get --vault open API_TOKEN | some-tool --token-stdin
tandemvault vault unset --vault open API_TOKEN                        # moves it to the vault's trash
tandemvault vault verify --vault open API_TOKEN < value-file          # "match" or "differs", never the value
```

`vault get` refuses to print to a terminal unless you pass `--reveal`. Reading from the sealed vault asks for its passphrase once per process.

### With agents

The two vaults map onto how much you want an agent to reach:

- Put what an agent may use on its own into the **open vault**. It reads a value by naming it (`vault run NAME -- cmd`), so nothing is in its environment by default.
- Put what needs you into the **sealed vault**. An agent can add entries there, for example a password it just set on a new account, but reading back needs the passphrase. How the passphrase is provided is up to you: `op://` makes every unlock a 1Password approval, `command:` hands it to your own tool, `prompt` asks on the terminal.
- An agent never runs `sync`. It edits a vault or `mappings.yaml`, checks `tandemvault status --local` (exit code 1 means a sync is pending), and tells you to run the sync.
- For a 1Password login an agent needs only for one job, it requests a lease (`link --lease`), you sync, it does the job, it runs `tandemvault return`, and you sync once more if it changed anything. The vault copy is gone afterwards; see [Using an item for a while](docs/sync.md#using-an-item-for-a-while).

## How syncing works

Which way a value moves, what happens on a conflict, how links, leases, new items and breaking a sync work: [docs/sync.md](docs/sync.md).

The vault formats, their files and how to set them up by hand or share them with other tools: [docs/vaults.md](docs/vaults.md).

1Password backends, SDK integration, passkeys: [docs/onepassword.md](docs/onepassword.md).

## Security model

tandemvault aims for a lock that is hard enough to pick while staying easy to use. What it does:

- Values never go on a command line, into a log, into the plan or into `state.json`. Values reach `sops` and `op` over pipes. The state file holds item versions and ciphertext hashes only.
- A sync shows its plan and asks before it writes, and re-checks both sides right before each write. An item that changed since the plan is left alone.
- Nothing is deleted for good: a 1Password item goes to Recently Deleted, a vault entry to the vault's trash, and 1Password is always written first, so its item history keeps every value a sync replaces.
- Replacing or removing a sealed entry needs the passphrase, and unlocking checks that the published recipient still belongs to the sealed identity.
- Releases are built from the tagged source on GitHub-hosted runners, checksummed and attested.

What it does not do: protect against code that already runs as your user. Such code can read the open vault and anything a running process holds, whatever tool you use.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
