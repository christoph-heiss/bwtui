// SPDX-License-Identifier: MIT

mod login;
mod vault;

fn main() {
    let mut siv = cursive::default();

    if let Ok(vault) = vault::read_local_data() {
        siv.set_user_data(vault);
    }

    login::create(&mut siv);
    siv.run();
}
