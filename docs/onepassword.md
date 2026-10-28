# 1Password

## Backends

```yaml
onepassword:
  account: my.1password.com   # sidebar name or account UUID
  backend: sdk                # sdk (default) or cli
```

**`sdk`** uses the [1Password Go SDK](https://github.com/1password/onepassword-sdk-go) with desktop app integration. The app shows an approval prompt once per tandemvault process and names the binary asking (`/usr/bin/tandemvault` for the packages). This also works when tandemvault runs in a shell without a terminal, for example over ssh: the prompt appears on the desktop. Items are read, one field is changed, and the item is written back; fields the SDK does not show, passkeys among them, are kept.

Turn the integration on once: in the 1Password app, open **Settings → Developer** and select **Integrate with other apps**. For fingerprint approval, also turn on system authentication under **Settings → Security**.

**`cli`** runs the [op command](https://developer.1password.com/docs/cli/) with its desktop app integration (**Settings → Developer → Integrate with 1Password CLI**). `op` can only edit an item by receiving the whole item back as a JSON template on stdin. tandemvault reads the full item, changes the synced fields and sends it back, which keeps every other field, section, URL and note, but 1Password's documentation says such a template replaces passkeys. So the `cli` backend edits only items mapped with `passkey: false`; see [Passkeys](#passkeys).

Both backends read values into the tandemvault process only. Nothing secret goes on a command line.

## What is written

- Login fields `username` and `password`, the item's one-time password field, and the primary website URL. A missing field is added; a new one-time password field goes into the item's first section.
- New items are Login items.
- Deleting (`unlink --keep vault`) moves the item to Recently Deleted.

## Passkeys

Neither the SDK nor `op` shows whether an item holds a passkey, so tandemvault cannot detect one.

- With the `sdk` backend this does not matter: an SDK edit keeps the passkey, and signing in with it still works afterwards.
- With the `cli` backend, an edit would replace the passkey. A mapping may therefore say `passkey: true` or `passkey: false` (`link --passkey` / `--no-passkey`), and the `cli` backend edits only items with `passkey: false`. For every other item the plan shows vault → 1Password changes as `skipped (passkey)` and leaves them pending; 1Password → vault changes still apply. When 1Password wins a conflict on such an item, the vault's losing value goes to the vault's trash instead of 1Password's history.

Deleting an item (`unlink --keep vault`) moves it to Recently Deleted with both backends, passkey included.

## Vault IDs

Mappings and `--op-vault` name 1Password vaults by ID, never by title: the SDK and `op` can show the same vault under different names (the personal vault of a business account, for one). `tandemvault vaults` lists the IDs.
