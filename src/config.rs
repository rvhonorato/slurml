use std::env;

#[derive(Clone)]
pub struct Config {
    pub secret_pass: String,
    pub jwt_key: String,
}

impl Config {
    pub fn new() -> Result<Self, &'static str> {
        let secret_pass =
            env::var("SECRETPASS").map_err(|_| "SECRETPASS system variable not set")?;
        let jwt_key = env::var("JWTKEY").map_err(|_| "JWTKEY system variable not set")?;

        // let secret_pass = "password".to_string();
        // let jwt_key = "key".to_string();

        Ok(Config {
            secret_pass,
            jwt_key,
        })
    }
}
