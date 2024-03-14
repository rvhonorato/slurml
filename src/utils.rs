use rand::{distributions::Alphanumeric, Rng};

pub fn generate_username() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10) // Username length
        .map(char::from)
        .collect()
}

pub fn generate_password() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(42)
        .map(char::from)
        .collect()
}
