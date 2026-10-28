# Vault formats

Both formats are plain files that other tools can read and write too. tandemvault adds no metadata to them.

## Open vault: `sops-dotenv`

One dotenv file encrypted with [sops](https://github.com/getsops/sops) and age. Names are in clear, each value is an `ENC[...]` blob:

```
API_TOKEN=ENC[AES256_GCM,data:...,type:str]
SHOP_PASSWORD=ENC[AES256_GCM,data:...,type:str]
sops_age__list_0__map_recipient=age1...
...
```

```yaml
vaults:
  open:
    type: sops-dotenv
    path: ~/.local/share/tandemvault/open.env
    age_key_file: ~/.config/sops/age/keys.txt   # optional
```

- Reading runs `sops -d`, which needs the age key: `age_key_file` if set, else whatever sops finds itself (`$SOPS_AGE_KEY_FILE`, then `~/.config/sops/age/keys.txt`).
- Writing runs `sops set --value-stdin` for one key. The other keys' blobs stay byte-identical, which is how a changed entry is spotted without decrypting.
- `tandemvault vault init` creates an empty file encrypted to the recipients of the age key, or to those given with `--age-recipient`. To create one by hand: `printf '' | sops encrypt --age <recipient> --input-type dotenv --output-type dotenv /dev/stdin > open.env`.
- A value that starts and ends with the same quote character is stored with one extra pair of quotes, because dotenv readers strip one pair. Read back through tandemvault (or sops' JSON output plus that rule), it comes out unchanged.
- Writers take an exclusive `flock` on `$XDG_RUNTIME_DIR/secret-store-<first 16 hex digits of sha256(absolute path)>.lock`. Another tool writing the same file can take the same lock so that two writers never lose each other's change.

## Sealed vault: `age-dir`

A directory with one armored age file per name, encrypted to a published X25519 recipient. The matching identity is stored beside it, sealed with a passphrase (age's scrypt mode):

```
sealed/
  SHOP_PASSWORD.age
  SHOP_USER.age
sealed-identity.age     # the identity, passphrase-encrypted
sealed.recipient        # its public recipient, age1...
```

```yaml
vaults:
  sealed:
    type: age-dir
    dir: ~/.local/share/tandemvault/sealed
    identity: ~/.local/share/tandemvault/sealed-identity.age   # default: <dir>-identity.age
    recipient: ~/.local/share/tandemvault/sealed.recipient     # default: <dir>.recipient
    passphrase: op://Private/tandemvault sealed vault/password
```

- Adding an entry needs only the recipient, so anything can drop a secret in.
- Reading, replacing and removing an entry unseal the identity first. Unsealing also checks that the identity still derives the published recipient: the recipient file can be written without the passphrase, and a swapped one would silently send every new entry to someone else's key.
- `passphrase` is one of:
  - `op://vault/item/field`: read from 1Password, through the same connection a sync uses, so a sync still needs one approval.
  - `command:<shell command>`: the command's standard output, without the trailing newline.
  - `prompt`: asked on the terminal.
- `tandemvault vault init` generates the identity, seals it, writes the recipient and creates the directory. The passphrase must have at least 12 characters. By hand with the age tools:

  ```bash
  age-keygen 2>/dev/null | tee >(age-keygen -y > sealed.recipient) | age -p -a > sealed-identity.age
  mkdir -m 700 sealed
  ```

- Every file is written through a temporary file and a rename, mode 0600.

## Trash

Removing an entry (`vault unset`, `unlink --keep op`, or a conflict the vault loses on an item 1Password may not be written) moves it instead of deleting it:

- open vault: into a second sops file beside it, `.trash` before the extension (`open.env` → `open.trash.env`), as `<NAME>__<UTC time>`.
- sealed vault: into `<dir>/.trash/<UTC time>/<NAME>.age`.

Emptying the trash is up to you.

## Syncing vaults between machines

The files work well with a file sync such as Syncthing: entries are separate files or separate lines, and the state file records ciphertext hashes, so `status --local` works on every machine. `sync` itself needs the 1Password app, so run it where the app is. A conflict copy blocks the next sync until it is resolved.
