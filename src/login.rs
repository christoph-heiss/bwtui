// SPDX-License-Identifier: MIT

use cursive::Cursive;
use cursive::direction::Orientation;
use cursive::event::Event;
use cursive::traits::*;
use cursive::views::{Dialog, EditView, LinearLayout, OnEventView, TextView};

use crate::{api, vault};
use api::{ApiError, AuthData, VaultData};


pub fn ask(siv: &mut Cursive, default_email: Option<String>) {
        let email_edit = EditView::new()
                .content(default_email.clone().unwrap_or("".to_owned()))
                .with_id("email");

        let email_view =
                OnEventView::new(email_edit)
                        .on_event(Event::CtrlChar('u'), |siv| {
                                if let Some(mut view) = siv.find_id::<EditView>("email") {
                                        view.set_content("")(siv);
                                }
                        });

        let password_edit = EditView::new()
                .secret()
                .with_id("master_password");

        let password_view =
                OnEventView::new(password_edit)
                        .on_event(Event::CtrlChar('u'), |siv| {
                                if let Some(mut view) = siv.find_id::<EditView>("master_password") {
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
                                        .call_on_id("email", |view: &mut EditView| {
                                                view.get_content()
                                        })
                                        .unwrap()
                                        .to_string();

                                let password = siv
                                        .call_on_id("master_password", |view: &mut EditView| {
                                                view.get_content()
                                        })
                                        .unwrap();

                                check_master_password(siv, email, &password);
                        })
                        .min_width(60)
        );

        if default_email.is_some() {
                siv.focus_id("master_password").unwrap();
        }
}


fn check_master_password(siv: &mut Cursive, email: String, master_password: &str) {
        let auth_data = api::authenticate(&email, &master_password);

        match auth_data {
                Ok(mut auth_data) => {
                        siv.pop_layer();

                        let vault_data =
                                if let Some(vault_data) = siv.take_user_data::<VaultData>() {
                                        vault_data
                                } else {
                                        sync_vault_data(siv, &auth_data).unwrap()
                                };

                        auth_data.cipher.set_decrypt_key(&vault_data.profile.key);
                        vault::show(siv, auth_data, vault_data);
                },
                Err(_) => {
                        siv.add_layer(Dialog::info("Wrong vault password"))
                },
        }
}


fn sync_vault_data(siv: &mut Cursive, auth_data: &AuthData) -> Result<VaultData, ApiError> {
        match api::sync(&auth_data) {
                Ok(vault_data) => {
                        if let Err(err) = api::save_vault_data(&vault_data) {
                                siv.add_layer(Dialog::info(err.to_string()));
                        }

                        Ok(vault_data)
                },
                Err(err) => {
                        siv.add_layer(Dialog::info(err.to_string()));
                        Err(err)
                }
        }
}
