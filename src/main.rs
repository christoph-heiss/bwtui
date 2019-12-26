// SPDX-License-Identifier: MIT

use cursive::backend::termion::Backend;
use cursive::Cursive;
use cursive_buffered_backend::BufferedBackend;

mod api;
mod cipher;
mod login;
mod vault;


fn main() {
        // We need to use a buffered backend due to flickering with termion.
        let mut siv = Cursive::new(|| {
                let backend = Backend::init().unwrap();
                let buffered = BufferedBackend::new(backend);

                Box::new(buffered)
        });

        let mut email = None;
        if let Ok(data) = api::read_app_data() {
                email = Some(data.vault.profile.email.clone());
                siv.set_user_data(data);
        }

        login::ask(&mut siv, email);

        siv.run();
}
