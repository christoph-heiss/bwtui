# bwtui

Small and simple TUI (terminal user interface) for your bitwarden vault.

Currently only supports reading/copying usernames and passwords for items.

## Controls
- general: `<esc>` or `ctrl-c` to exit
- login: `<tab>` to move between email, password and ok button
- vault: `j/k` move up/down, `ctrl-u` copy username, `ctrl-p` copy password

## Installation

Either directly from git using:
```bash
cargo install --git https://github.com/christoph-heiss/bwtui.git
```

or from [crates.io](https://crates.io/crates/bwtui):
```bash
cargo install bwtui
```

## TODO list

`bwtui` still got lots of rough edges:

- [ ] better error handling/propagating
- [ ] configurable shortcuts
- [ ] (optional) clipboard clearing after x seconds
- [ ] (optional) vault locking after x seconds
- [ ] re-sync with bitwarden server
- [ ] domain list support
- [ ] login URI launching
- [ ] card/identity/note support
- [ ] folder support
- [ ] item totp/notes/custom field support
- [ ] support for on-premise servers
- [ ] check some of the crypto stuff (especially hmac stuff)
- [ ] (maybe) editing of vault items
