# Moved to [git.sr.ht/~c8h4/bwtui](https://git.sr.ht/~c8h4/bwtui)!

Old README:

# bwtui

Small and simple TUI (terminal user interface) for your bitwarden vault.

Currently only supports reading/copying usernames and passwords for items.

## Controls
- general: `ctrl-c` to exit
- login: `<tab>` to move between email, password and ok button
- vault: `j/k` move up/down, `J/K` to move to first/last item, `ctrl-u` copy username, `ctrl-p` copy password, `ctrl-f` fuzzy search

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

- [x] ~~offline support~~
- [ ] better error handling/propagating
- [ ] configurable shortcuts
- [ ] (optional) clipboard clearing after x seconds
- [ ] (optional) vault locking after x seconds
- [ ] re-sync with bitwarden server / reuse of access token
- [ ] domain list support
- [ ] login URI launching
- [ ] card/identity/note support
- [ ] folder support
- [ ] item totp/notes/custom field support
- [ ] support for on-premise servers
- [ ] check some of the crypto stuff (especially hmac stuff)
- [ ] (maybe) editing of vault items

## License

Licensed under MIT license ([LICENSE](LICENSE) or https://opensource.org/licenses/MIT).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be licensed by MIT license as above, without any
additional terms or conditions.
