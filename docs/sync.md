# How syncing works

## The files

tandemvault keeps two files beside its configuration (paths can be changed with `mappings:` and `state:` in `config.yaml`):

- `mappings.yaml` lists the synced items. It holds names, IDs and directions, never a value, so it can be edited by anything without a key. `link` and `unlink` edit it; `sync` carries the edits out.
- `state.json` records, per mapping, the 1Password item version and the sha256 of each vault entry's ciphertext at the last sync. It holds nothing derived from a plaintext value.

A mapping looks like this:

```yaml
mappings:
  - vault: sealed
    prefix: SHOP
    item: abcdefghijklmnopqrstuvwxyz   # 1Password item ID, filled in once found
    op_vault: zyxwvutsrqponmlkjihgfedcba
    title: Example Shop
    fields: [username, password, otp]  # optional, default all four
    names: {username: SHOP_LOGIN}      # optional, per-field entry name
    passkey: false                     # optional, only read by the cli backend
```

Entry names default to `<PREFIX>_USER`, `<PREFIX>_PASSWORD`, `<PREFIX>_TOTP_SECRET` and `<PREFIX>_URL`.

`op_vault` is a vault ID (`tandemvault vaults` lists them). `passkey` is optional and only matters for the `cli` backend, which edits an item only when it is `false`; see [onepassword.md](onepassword.md#passkeys).

## Which way a value moves

For every field of every mapping, the sync compares the two values in memory. When they are equal, nothing happens. When they differ:

| What changed since the last sync | Result |
|---|---|
| only the vault entry | vault → 1Password |
| only the 1Password item | 1Password → vault |
| both, or there is no last sync | the newer side wins |
| one side is empty | it is filled from the other side |

"Changed" means the 1Password item's version moved, or the entry's ciphertext hash moved. The 1Password version is per item, so a change to a field tandemvault does not sync (the notes, say) also counts; a plain vault edit then becomes a conflict, decided by time and shown as such in the plan.

"Newer" compares the item's last update time with the entry's file time. For the open vault that is the time of the whole file, an upper bound for each entry, which tips close calls towards the vault.

An empty or missing value never overwrites a present one. To stop syncing a value, unlink the mapping.

1Password is always written first, so its item history holds every value a sync replaces:

- vault wins: one 1Password write. The old value moves to the item's history.
- 1Password wins a conflict: the vault's value is written to 1Password first, then 1Password's own value back on top, then the vault is updated. Both values are in the item's history.

One-time passwords compare by their secret and parameters, so `JBSW Y3DP …`, `jbswy3dp…` and an `otpauth://` URI with the same secret are equal. A vault receives the bare base32 secret when the parameters are the defaults (SHA1, 6 digits, 30 seconds) and the full `otpauth://` URI otherwise, so no parameter is lost. 1Password always receives an `otpauth://` URI. An item with more than one one-time password field is skipped for that field.

Only the primary URL of an item is synced. Its other URLs and their labels stay as they are.

## Plan, confirm, apply

`tandemvault sync` connects to 1Password, unlocks the vaults it needs, plans, prints the plan and asks. `--dry-run` stops after the plan. `tandemvault status` is the same as a dry run.

Before writing an item, the sync reads it again and compares its version and the vault fingerprints with what the plan saw. If either moved, that item is left alone and reported; run the sync again. The 1Password write itself also carries the expected version.

After the writes, the state is recorded. A run with nothing to change still records the state of every item it read.

The sync refuses to start while a file-sync conflict copy (`*.sync-conflict-*`, as Syncthing makes them) of a vault, `mappings.yaml`, `state.json` or the configuration exists. One of the two copies holds a change the other lacks, and only you can tell which.

## Linking an item

```bash
tandemvault link "Example Shop" --vault sealed --prefix SHOP
tandemvault link abcdefghijklmnopqrstuvwxyz --vault open --prefix FORUM --fields username,password
```

A link names the 1Password item by title or by item ID. The next sync looks it up, limited to the vault with the ID given as `--op-vault`, if any: by ID, else exact title, else title ignoring case, else titles containing the search ignoring case. The first of these that finds anything decides. One match is linked and synced in the same run; when it was not an exact match, the plan says so ("best match for …"), so you see which item was picked before you confirm. Several matches are listed with their IDs and titles and skipped; link by ID then.

Entries missing in the vault are created from 1Password.

## Creating a 1Password item from the vault

```bash
tandemvault link --create "New Forum" --op-vault zyxwvutsrqponmlkjihgfedcba --vault sealed --prefix NEWFORUM
```

The next sync creates a Login item titled "New Forum" from the vault entries `NEWFORUM_USER`, `NEWFORUM_PASSWORD`, `NEWFORUM_TOTP_SECRET` and `NEWFORUM_URL` (those that exist), and turns the request into a normal mapping.

## Using an item for a while

Sometimes a value is needed in the vault only for one job, for example to rotate a password, and should not stay there afterwards. That is a lease:

```bash
tandemvault link --lease "example shop" --vault sealed --prefix SHOP   # 1. request
tandemvault sync                                                        # 2. pull (approval 1)
# ... use SHOP_USER / SHOP_PASSWORD, or set a new SHOP_PASSWORD after changing it on the site ...
tandemvault return SHOP                                                 # 3. give it back
tandemvault sync                                                        # 4. write back and delete (approval 2)
```

`return` checks whether any of the mapping's vault entries changed since the last sync:

- Unchanged: 1Password already holds every value the vault has, so the entries are deleted at once, without a trash copy, and the mapping ends. No sync, no 1Password, no passphrase. Reading a value for a while therefore costs one sync.
- Changed: the mapping is marked, and the next sync writes the vault's values to 1Password like any sync, reads the item back, and checks that it holds each of them. Only then are the vault entries deleted (without a trash copy; 1Password's item history keeps every older value) and the mapping ends. If the check fails, the vault copy stays and the sync reports it. Changing a value for a while therefore costs two syncs.

`status --local` lists leases that are not returned yet. `return` works on any mapping, not only leases: it is how a vault copy is dropped once 1Password is known to have it.

If 1Password's own value changed in the meantime and is newer, 1Password keeps it and the vault's value goes into the item's history first, as in any conflict. A return the backend cannot carry out (the `cli` backend on an item not mapped with `passkey: false`) is skipped and the vault copy stays.

## Breaking a sync

```bash
tandemvault unlink SHOP --keep vault   # 1Password item → Recently Deleted
tandemvault unlink SHOP --keep op      # vault entries → vault trash
tandemvault unlink SHOP --keep both    # stop syncing, change nothing
tandemvault unlink SHOP --keep none    # retire: write back, then 1Password item → Recently Deleted, vault entries deleted
```

`--keep vault`, `--keep op` and `--keep none` mark the mapping; the next sync shows it in the plan, carries it out and removes the mapping. `--keep both` removes the mapping right away.

`--keep none` is for an account that is gone: the sync first writes the vault's values back and checks 1Password holds them, like a return, then moves the item to Recently Deleted and deletes the vault entries without a trash copy, since the deleted item holds them.

Nothing is lost for good: 1Password keeps deleted items in Recently Deleted, a vault keeps entries removed by `--keep op` or `vault unset` in its trash ([vaults.md](vaults.md#trash)), and entries deleted by a return or a retire were first checked to be in 1Password.

## Status without 1Password

```bash
tandemvault status --local
```

Needs neither 1Password nor a key. It lists pending links, create, return and unlink requests, leases not returned yet, vault entries whose ciphertext changed since the last sync, and conflict copies, and exits with 1 when anything is pending. Changes made in 1Password only show in a full `status` or `sync`. `--quiet` prints nothing and only sets the exit code.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done, nothing pending |
| 1 | something is pending, the plan was declined, or an item failed |
| 2 | usage, configuration or environment error |
