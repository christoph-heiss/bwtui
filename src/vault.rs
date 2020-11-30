// SPDX-License-Identifier: MIT

use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use cursive::event::{Event, Key};
use cursive::traits::*;
use cursive::views::{Dialog, DummyView, EditView, LinearLayout, OnEventView, TextView};
use cursive::Cursive;
use cursive_table_view::{TableView, TableViewItem};
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use serde::de::DeserializeOwned;
use serde::Serialize;
use unicase::UniCase;

use bitwarden::cipher::CipherSuite;
use bitwarden::{AuthData, CipherEntry, SyncResponse};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum VaultColumn {
    Favorite,
    Name,
    Username,
}

#[derive(Clone)]
pub struct VaultEntry {
    name: UniCase<String>,
    username: UniCase<String>,
    password: String,
    favorite: String,
}

pub struct VaultData {
    pub auth: AuthData,
    pub sync: SyncResponse,
    pub decrypted: Vec<VaultEntry>,
}

type VaultTableView = TableView<VaultEntry, VaultColumn>;

impl VaultEntry {
    pub fn from_cipher_entry(entry: &CipherEntry, cipher: &CipherSuite) -> Option<VaultEntry> {
        let favorite = if entry.favorite {
            "\u{2605}"
        } else {
            "\u{2606}"
        };

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
    where
        Self: Sized,
    {
        match column {
            VaultColumn::Favorite => self.favorite.cmp(&other.favorite),
            VaultColumn::Name => self.name.cmp(&other.name),
            VaultColumn::Username => self.username.cmp(&other.username),
        }
    }
}

pub fn create(siv: &mut Cursive) {
    let mut table = VaultTableView::new()
        .column(VaultColumn::Favorite, "", |c| c.width(1))
        .column(VaultColumn::Name, "Name", |c| c.width_percent(25))
        .column(VaultColumn::Username, "Username", |c| c)
        .items(siv.user_data::<VaultData>().unwrap().decrypted.clone());

    table.sort_by(VaultColumn::Name, Ordering::Less);
    table.sort_by(VaultColumn::Favorite, Ordering::Less);

    let table_view = OnEventView::new(table.with_name("password_table").full_screen())
        .on_event('j', |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                if let Some(row) = view.row() {
                    if row < view.len() - 1 {
                        view.set_selected_row(row + 1);
                    }
                }
            })
            .unwrap();
        })
        .on_event('k', |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                if let Some(row) = view.row() {
                    if row > 0 {
                        view.set_selected_row(row - 1);
                    }
                }
            })
            .unwrap();
        })
        .on_event('J', |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                view.set_selected_row(view.len() - 1);
            })
            .unwrap();
        })
        .on_event('K', |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                view.set_selected_row(0);
            })
            .unwrap();
        })
        .on_event(Event::CtrlChar('u'), |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                if let Some(row) = view.item() {
                    if let Some(entry) = view.borrow_item(row) {
                        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();

                        clipboard.set_contents(entry.username.to_string()).unwrap();
                    }
                }
            })
            .unwrap();
        })
        .on_event(Event::CtrlChar('p'), |siv| {
            siv.call_on_name("password_table", |view: &mut VaultTableView| {
                if let Some(row) = view.item() {
                    if let Some(entry) = view.borrow_item(row) {
                        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();

                        clipboard.set_contents(entry.password.clone()).unwrap();
                    }
                }
            })
            .unwrap();
        })
        .on_event(Event::CtrlChar('f'), |siv| {
            siv.focus_name("search_field").unwrap();
        });

    let search_field = EditView::new()
        .on_edit(move |siv, content, _| {
            fuzzy_match_on_edit(siv, content);
        })
        .with_name("search_field")
        .full_width();

    let search_view = LinearLayout::horizontal()
        .child(TextView::new("search: "))
        .child(
            OnEventView::new(search_field)
                .on_event(Event::CtrlChar('f'), |siv| {
                    siv.focus_name("password_table").unwrap();
                })
                .on_event(Key::Esc, |siv| {
                    siv.focus_name("password_table").unwrap();
                })
                .on_event(Key::Enter, |siv| {
                    siv.focus_name("password_table").unwrap();
                })
                .on_event(Event::CtrlChar('u'), |siv| {
                    if let Some(mut view) = siv.find_name::<EditView>("search_field") {
                        view.set_content("")(siv);
                    }
                }),
        );

    let main_view = LinearLayout::vertical()
        .child(search_view)
        .child(DummyView)
        .child(table_view);

    let layout = LinearLayout::vertical()
        .child(
            Dialog::around(main_view)
                .title("bitwarden vault")
                .padding_top(1),
        )
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("^C: Quit  ^U: Copy username  ^P: Copy password").full_width())
                .child(TextView::new("^F: fuzzy-search")),
        );

    siv.clear();
    siv.add_fullscreen_layer(layout);
    siv.focus_name("password_table").unwrap();
}

pub fn decrypt(vault: &mut VaultData) {
    vault.decrypted = vault.sync
        .ciphers
        .iter()
        .map(|c| VaultEntry::from_cipher_entry(&c, &vault.auth.cipher).unwrap())
        .collect();
}

fn fuzzy_match_on_edit(siv: &mut Cursive, content: &str) {
    let mut table = siv.find_name::<VaultTableView>("password_table").unwrap();
    let items = &siv.user_data::<VaultData>().unwrap().decrypted;

    // If no search term is present, sort by name and favorite by default
    if content.is_empty() {
        table.set_items(items.clone());
        table.sort_by(VaultColumn::Name, Ordering::Less);
        table.sort_by(VaultColumn::Favorite, Ordering::Less);
        return;
    }

    let matcher = SkimMatcherV2::default();
    let mut items: Vec<(i64, VaultEntry)> = items.iter()
        .map(|entry| {
            (matcher.fuzzy_match(&entry.name, content), entry.clone())
        })
        .filter(|(score, _)| score.is_some())
        .map(|(score, entry)| (score.unwrap(), entry))
        .collect();

    items.sort_by(|a, b| a.0.cmp(&b.0).reverse());

    let items = items.iter().map(|(_, entry)| entry.clone()).collect();
    table.set_selected_row(0);
    table.set_items(items);
}

fn get_app_data_path() -> Result<PathBuf, String> {
    let project_dirs = directories::ProjectDirs::from("", "", "bwtui")
        .ok_or("could not retrieve data directory path")?;

    let target_dir = project_dirs.data_local_dir();

    fs::create_dir_all(target_dir).map_err(|_| "could not create data directory")?;

    let mut path = PathBuf::new();
    path.push(target_dir);

    Ok(path)
}

fn save_data_to<T>(filename: &str, data: &T) -> Result<(), String>
where
    T: Serialize,
{
    let mut path = get_app_data_path()
        .map_err(|err| format!("failed to write sync data: {}", err))?;

    path.push(filename);

    let file = File::create(path)
        .map_err(|err| format!("failed to write sync data: {}", err))?;

    let writer = BufWriter::new(file);
    serde_json::to_writer(writer, data)
        .map_err(|err| format!("failed to write sync data: {}", err))
}

fn read_data_from<T>(filename: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let mut path = get_app_data_path()
        .map_err(|err| format!("failed to read sync data: {}", err))?;

    path.push(filename);

    let file = File::open(path)
        .map_err(|err| format!("failed to read sync data: {}", err))?;

    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .map_err(|err| format!("failed to read sync data: {}", err))
}

pub fn read_local_data() -> Result<VaultData, String> {
    let auth = read_data_from("auth.json")?;
    let sync = read_data_from("vault.json")?;

    Ok(VaultData { auth, sync, decrypted: Vec::new() })
}

pub fn save_local_data(data: &VaultData) -> Result<(), String> {
    save_data_to("auth.json", &data.auth)?;
    save_data_to("vault.json", &data.sync)?;

    Ok(())
}
