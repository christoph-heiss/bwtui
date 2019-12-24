// SPDX-License-Identifier: MIT

use std::cmp::Ordering;

use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};

use cursive::Cursive;
use cursive::event::{Event, Key};
use cursive::traits::*;
use cursive::views::{Dialog, DummyView, EditView, LinearLayout, OnEventView, TextView};
use cursive_table_view::{TableView, TableViewItem};

use unicase::UniCase;

use crate::api::{AuthData, CipherEntry, VaultData};
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

type VaultTableView = TableView::<VaultEntry, VaultColumn>;


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

        fn cmp(&self, other: &Self, column: VaultColumn) -> Ordering
                where Self: Sized,
        {
                match column {
                        VaultColumn::Favorite => self.favorite.cmp(&other.favorite),
                        VaultColumn::Name => self.name.cmp(&other.name),
                        VaultColumn::Username => self.username.cmp(&other.username),
                }
        }
}


pub fn show(siv: &mut Cursive, auth_data: AuthData, vault_data: VaultData) {
        let items = vault_data.ciphers
                .iter()
                .map(|c| VaultEntry::from_cipher_entry(&c, &auth_data.cipher).unwrap())
                .collect::<Vec<VaultEntry>>();

        let mut table = VaultTableView::new()
                .column(VaultColumn::Favorite, "", |c| c.width(1))
                .column(VaultColumn::Name, "Name", |c| c.width_percent(25))
                .column(VaultColumn::Username, "Username", |c| c)
                .items(items.clone());

        table.sort_by(VaultColumn::Name, Ordering::Less);
        table.sort_by(VaultColumn::Favorite, Ordering::Less);

        let table_view = OnEventView::new(
                        table
                                .with_id("password_table")
                                .full_screen()
                )
                .on_event('j', |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.row() {
                                        if row < view.len()-1 {
                                                view.set_selected_row(row + 1);
                                        }
                                }
                        })
                        .unwrap();
                })
                .on_event('k', |siv| {
                        siv.call_on_id("password_table", |view: &mut VaultTableView| {
                                if let Some(row) = view.row() {
                                        if row > 0 {
                                                view.set_selected_row(row - 1);
                                        }
                                }
                        })
                        .unwrap();
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
                        .unwrap();
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
                        .unwrap();
                })
                .on_event(Event::CtrlChar('f'), |siv| {
                        siv.focus_id("search_field").unwrap();
                });

        let search_field =
                EditView::new()
                        .on_edit(move |siv, content, _| {
                                fuzzy_match_on_edit(siv, &items, content);
                        })
                        .with_id("search_field")
                        .full_width();

        let search_view = LinearLayout::horizontal()
                .child(TextView::new("search: "))
                .child(
                        OnEventView::new(search_field)
                                .on_event(Event::CtrlChar('f'), |siv| {
                                        siv.focus_id("password_table").unwrap();
                                })
                                .on_event(Key::Esc, |siv| {
                                        siv.focus_id("password_table").unwrap();
                                })
                                .on_event(Key::Enter, |siv| {
                                        siv.focus_id("password_table").unwrap();
                                })
                                .on_event(Event::CtrlChar('u'), |siv| {
                                        if let Some(mut view) = siv.find_id::<EditView>("search_field") {
                                                view.set_content("")(siv);
                                        }
                                })
                );

        let main_view = LinearLayout::vertical()
                .child(search_view)
                .child(DummyView)
                .child(table_view);

        let layout = LinearLayout::vertical()
                .child(
                        Dialog::around(main_view)
                                .title("bitwarden vault")
                                .padding_top(1)
                )
                .child(
                        LinearLayout::horizontal()
                                .child(TextView::new("^U: Copy username  ^P: Copy password").full_width())
                                .child(TextView::new("^F: fuzzy-search"))
                );

        siv.add_layer(layout);
        siv.focus_id("password_table").unwrap();
}


fn fuzzy_match_on_edit(siv: &mut Cursive, items: &Vec<VaultEntry>, content: &str) {
        let mut table = siv.find_id::<VaultTableView>("password_table").unwrap();

        // If no search term is present, sort by name and favorite by default
        if content.len() == 0 {
                table.set_items(items.clone());

                table.sort_by(VaultColumn::Name, Ordering::Less);
                table.sort_by(VaultColumn::Favorite, Ordering::Less);

                return;
        }

        let matcher = SkimMatcherV2::default();

        let mut items: Vec<(i64, VaultEntry)> = items
                .iter()
                .map(|entry| {
                        (matcher.fuzzy_match(&entry.name, content), entry.clone())
                })
                .filter(|(score, _)| score.is_some())
                .map(|(score, entry)| (score.unwrap(), entry))
                .collect();

        items.sort_by(|a, b| a.0.cmp(&b.0).reverse());

        let items = items
                .iter()
                .map(|(_, entry)| entry.clone())
                .collect();

        table.set_selected_row(0);
        table.set_items(items);
}
