// SPDX-License-Identifier: MIT

use std::cmp;

use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

use cursive::Cursive;
use cursive::direction::Orientation;
use cursive::event::Event;
use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, OnEventView, TextView};
use cursive_table_view::{TableView, TableViewItem};

use unicase::UniCase;

use crate::api::{self, CipherEntry};
use crate::cipher::CipherSuite;


#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum VaultColumn {
        Favorite,
        Name,
        Username,
}

#[derive(Clone, Debug)]
struct VaultEntry {
        name: UniCase<String>,
        username: UniCase<String>,
        password: String,
        favorite: String,
}

impl VaultEntry {
        fn from_cipher_entry(entry: &CipherEntry, cipher: &CipherSuite) -> Option<VaultEntry> {
                let favorite = if entry.favorite { "\u{2605}" } else { "\u{2606}" };

                Some(Self {
                        name: UniCase::new(entry.name.decrypt(cipher)?),
                        username: UniCase::new(entry.data.username.decrypt(cipher)?),
                        password: entry.data.password.decrypt(cipher)?,
                        favorite: favorite.to_owned(),
                })
        }
}

impl TableViewItem<VaultColumn> for VaultEntry {
        fn to_column(&self, column: VaultColumn) -> String {
                match column {
                        VaultColumn::Favorite => self.favorite.clone(),
                        VaultColumn::Name => self.name.to_string(),
                        VaultColumn::Username => self.username.to_string(),
                }
        }

        fn cmp(&self, other: &Self, column: VaultColumn) -> cmp::Ordering
                where Self: Sized,
        {
                match column {
                        VaultColumn::Favorite => self.favorite.cmp(&other.favorite),
                        VaultColumn::Name => self.name.cmp(&other.name),
                        VaultColumn::Username => self.username.cmp(&other.username),
                }
        }
}

type VaultTableView = TableView::<VaultEntry, VaultColumn>;


pub fn show(siv: &mut Cursive, auth_data: api::AuthData, vault_data: api::VaultData) {
        let items = vault_data.ciphers
                .iter()
                .map(|c| VaultEntry::from_cipher_entry(&c, &auth_data.cipher).unwrap())
                .collect();


        let mut table = VaultTableView::new()
                .column(VaultColumn::Favorite, "", |c| c.width(1))
                .column(VaultColumn::Name, "Name", |c| c.width_percent(25))
                .column(VaultColumn::Username, "Username", |c| c)
                .items(items);

        table.sort_by(VaultColumn::Name, cmp::Ordering::Less);
        table.sort_by(VaultColumn::Favorite, cmp::Ordering::Less);

        let view = OnEventView::new(
                        table
                                .with_id("password_table")
                                .min_size((100, 50))
                )
                .on_event('j', |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.row() {
                                        if row < view.len()-1 {
                                                view.set_selected_row(row + 1);
                                        }
                                }
                        })
                        .unwrap()
                })
                .on_event('k', |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.row() {
                                        if row > 0 {
                                                view.set_selected_row(row - 1);
                                        }
                                }
                        })
                        .unwrap()
                })
                .on_event(Event::CtrlChar('u'), |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.item() {
                                        if let Some(entry) = view.borrow_item(row) {
                                                let mut clipboard: ClipboardContext = ClipboardProvider::new()
                                                        .unwrap();

                                                clipboard
                                                        .set_contents(entry.username.to_string())
                                                        .unwrap();
                                        }
                                }
                        })
                        .unwrap()
                })
                .on_event(Event::CtrlChar('p'), |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.item() {
                                        if let Some(entry) = view.borrow_item(row) {
                                                let mut clipboard: ClipboardContext = ClipboardProvider::new()
                                                        .unwrap();

                                                clipboard
                                                        .set_contents(entry.password.clone())
                                                        .unwrap();
                                        }
                                }
                        })
                        .unwrap()
                });

        let layout = LinearLayout::new(Orientation::Vertical)
                .child(
                        Dialog::around(view)
                                .title("bitwarden vault")
                )
                .child(
                        TextView::new("^U: Copy username  ^P: Copy password")
                );

        siv.add_layer(layout);
}
