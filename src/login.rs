// SPDX-License-Identifier: MIT

use cursive::direction::Orientation;
use cursive::event::Event;
use cursive::traits::*;
use cursive::views::{Dialog, EditView, LinearLayout, OnEventView, TextView};
use cursive::Cursive;

use bitwarden::cipher::CipherSuite;
use bitwarden::{self, ApiError, AppData, AuthData, VaultData};

use crate::vault;

pub fn ask(siv: &mut Cursive, default_email: Option<String>) {
    let email_edit = EditView::new()
        .content(default_email.clone().unwrap_or("".to_owned()))
        .with_name("email");

    let email_view = OnEventView::new(email_edit).on_event(Event::CtrlChar('u'), |siv| {
        if let Some(mut view) = siv.find_name::<EditView>("email") {
            view.set_content("")(siv);
        }
    });

    let password_edit = EditView::new().secret().with_name("master_password");

    let password_view = OnEventView::new(password_edit).on_event(Event::CtrlChar('u'), |siv| {
        if let Some(mut view) = siv.find_name::<EditView>("master_password") {
            view.set_content("")(siv);
        }
    });

    let layout = LinearLayout::new(Orientation::Vertical)
        .child(TextView::new("email address:"))
        .child(email_view)
        .child(TextView::new("master password:"))
        .child(password_view);

    siv.add_layer(
        Dialog::around(layout)
            .title("bitwarden vault login")
            .button("Ok", |siv| {
                let email = siv
                    .call_on_name("email", |view: &mut EditView| view.get_content())
                    .unwrap()
                    .to_string();

                let password = siv
                    .call_on_name("master_password", |view: &mut EditView| view.get_content())
                    .unwrap();

                check_master_password(siv, email, &password);
            })
            .min_width(60),
    );

    if default_email.is_some() {
        siv.focus_name("master_password").unwrap();
    }
}

fn check_master_password(siv: &mut Cursive, email: String, master_password: &str) {
    if let Some(app_data) = siv.take_user_data::<AppData>() {
        let AppData { mut auth, vault } = app_data;

        auth.cipher = CipherSuite::from(&email, master_password, auth.kdf_iterations);

        if let Err(_) = auth.cipher.set_decrypt_key(&vault.profile.key) {
            siv.add_layer(Dialog::info("Wrong vault password"));
        } else {
            vault::show(siv, auth, vault);
        }

        return;
    }

    let auth_data = bitwarden::authenticate(&email, &master_password);

    match auth_data {
        Ok(mut auth_data) => {
            siv.pop_layer();

            let vault = sync_vault_data(siv, &auth_data).unwrap();

            if let Err(_) = auth_data.cipher.set_decrypt_key(&vault.profile.key) {
                siv.add_layer(Dialog::info("Wrong vault password"));
            } else {
                vault::show(siv, auth_data, vault);
            }
        }
        Err(_) => siv.add_layer(Dialog::info("Wrong vault password")),
    }
}

fn sync_vault_data(siv: &mut Cursive, auth_data: &AuthData) -> Result<VaultData, ApiError> {
    match bitwarden::sync(&auth_data) {
        Ok(vault_data) => {
            if let Err(err) = vault::save_app_data(&auth_data, &vault_data) {
                siv.add_layer(Dialog::info(err.to_string()));
            }

            Ok(vault_data)
        }
        Err(err) => {
            siv.add_layer(Dialog::info(err.to_string()));
            Err(err)
        }
    }
}
