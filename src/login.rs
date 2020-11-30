// SPDX-License-Identifier: MIT

use std::sync::mpsc;
use std::thread;

use cursive::direction::Orientation;
use cursive::event::Event;
use cursive::traits::*;
use cursive::views::{Dialog, EditView, LinearLayout, OnEventView, TextContent, TextView};
use cursive::{CbSink as CursiveSink, Cursive};

use bitwarden::cipher::CipherSuite;
use bitwarden::{self, ApiError, AuthData};

use crate::vault::{self, VaultData};

enum LoginProgress {
    Decrypting,
    Syncing,
    Finished(VaultData),
    Error(Option<VaultData>, ApiError),
}

type LoginProgressSink = mpsc::Sender<LoginProgress>;
type LoginProgressRecv = mpsc::Receiver<LoginProgress>;

pub fn create(siv: &mut Cursive) {
    let email_edit = EditView::new().with_name("email");
    let email_view = OnEventView::new(email_edit).on_event(Event::CtrlChar('u'), |siv| {
        siv.find_name::<EditView>("email").unwrap().set_content("")(siv);
    });

    let password_edit = EditView::new().secret().with_name("master_password");
    let password_view = OnEventView::new(password_edit).on_event(Event::CtrlChar('u'), |siv| {
        siv.find_name::<EditView>("master_password").unwrap().set_content("")(siv);
    });

    let layout = LinearLayout::new(Orientation::Vertical)
        .child(TextView::new("email address:"))
        .child(email_view)
        .child(TextView::new("master password:"))
        .child(password_view);

    let dialog = Dialog::around(layout)
        .title("bitwarden vault login")
        .button("Ok", on_login)
        .min_width(60);

    siv.clear();
    siv.add_layer(dialog);

    if let Some(email) = siv.user_data().map(|data: &mut VaultData| data.sync.profile.email.clone()) {
        siv.find_name::<EditView>("email").unwrap().set_content(email)(siv);
        siv.focus_name("master_password").unwrap();
    }
}

fn on_login(siv: &mut Cursive) {
    let email = siv.find_name::<EditView>("email").unwrap().get_content().to_string();
    let password = siv.find_name::<EditView>("master_password").unwrap().get_content().to_string();

    siv.set_autorefresh(true);
    let progress_text = TextContent::new("authenticating ...");
    let progress_view = TextView::new_with_content(progress_text.clone());
    let progress_dialog = Dialog::around(progress_view).with_name("progress_dialog");
    siv.add_layer(progress_dialog);

    let vault_data = siv.take_user_data();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Some(data) = vault_data {
            decrypt_cached(tx, data, &email, &password);
        } else {
            sync_and_decrypt(tx, &email, &password);
        }
    });

    let cb_sink = siv.cb_sink().clone();
    thread::spawn(move || {
        process_login(cb_sink, rx, progress_text);
    });
}

fn decrypt_cached(
    sink: LoginProgressSink,
    mut vault: VaultData,
    email: &str,
    master_password: &str
) {
    sink.send(LoginProgress::Decrypting).unwrap();
    vault.auth.cipher = CipherSuite::from(&email, master_password, vault.auth.kdf_iterations);

    if vault.auth.cipher.set_decrypt_key(&vault.sync.profile.key).is_err() {
        sink.send(
            LoginProgress::Error(Some(vault), ApiError::LoginFailed)
        ).unwrap();
    } else {
        vault::decrypt(&mut vault);
        sink.send(LoginProgress::Finished(vault)).unwrap();
    }
}

fn sync_and_decrypt(sink: LoginProgressSink, email: &str, master_password: &str) {
    match bitwarden::authenticate(&email, &master_password) {
        Ok(auth) => {
            sink.send(LoginProgress::Syncing).unwrap();
            let vault = sync_vault_data(auth).unwrap();

            decrypt_cached(sink, vault, email, master_password);
        },
        Err(err) => sink.send(LoginProgress::Error(None, err)).unwrap(),
    }
}

fn process_login(sink: CursiveSink, recv: LoginProgressRecv, progress_text: TextContent) {
    for progress in recv.iter() {
        match progress {
            LoginProgress::Decrypting => {
                progress_text.set_content("decrypting ...");
             },

            LoginProgress::Syncing => {
                progress_text.set_content("syncing ...");
            },

            LoginProgress::Finished(vault) => {
                sink.send(Box::new(|siv| {
                    siv.set_user_data(vault);
                    vault::create(siv);
                })).unwrap();
                break;
            },

            LoginProgress::Error(vault, err) => {
                sink.send(Box::new(move |siv| {
                    siv.pop_layer();
                    siv.find_name::<EditView>("master_password").unwrap().set_content("")(siv);

                    if let Some(vault) = vault {
                        siv.set_user_data(vault);
                    }

                    siv.add_layer(Dialog::info(err.to_string()));
                })).unwrap();
                break;
            },
        }
    }

    sink.send(Box::new(|siv| {
        siv.set_autorefresh(false);
    })).unwrap();
}

fn sync_vault_data(auth: AuthData) -> Result<VaultData, String> {
    bitwarden::sync(&auth)
        .map(|sync| VaultData { auth, sync, decrypted: Vec::new() })
        .map_err(|e| e.to_string())
        .and_then(|vault| vault::save_local_data(&vault).and(Ok(vault)))
}
