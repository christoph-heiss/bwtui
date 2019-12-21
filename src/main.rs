// SPDX-License-Identifier: MIT

use cursive::backend::termion::Backend;
use cursive::Cursive;
use cursive::event::Key;
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

        #[cfg(debug_assertions)]
        cursive::logger::init();
        #[cfg(debug_assertions)]
        siv.add_global_callback(Key::F1, |s| s.toggle_debug_console());

        siv.add_global_callback(Key::Esc, |s| s.quit());

        let mut email = None;
        if let Ok(data) = api::read_local_vault_data() {
                email = Some(data.profile.email.clone());
                siv.set_user_data(data);
        }

        login::ask(&mut siv, email);

        siv.run();
}
