// SPDX-License-Identifier: MIT

mod login;
mod vault;

use cursive::backends::termion::Backend;
use cursive::Cursive;
use cursive_buffered_backend::BufferedBackend;

fn main() {
    // We need to use a buffered backend due to flickering with termion.
    let mut siv = Cursive::new(|| {
        let backend = Backend::init().unwrap();
        let buffered = BufferedBackend::new(backend);

        Box::new(buffered)
    });

    if let Ok(vault) = vault::read_local_data() {
        siv.set_user_data(vault);
    }

    login::create(&mut siv);
    siv.run();
}
