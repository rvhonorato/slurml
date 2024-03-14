#[derive(Clone)]
pub struct Config {
    pub jwt_key: String,
    // pub db_path: String,
}

impl Config {
    pub fn new() -> Result<Self, &'static str> {
        // let db_path = "db.sqlite".to_string();
        let jwt_key = "key".to_string();

        // // Define db_path as DATABASE_URL
        // let db_path = match std::env::var("DATABASE_URL") {
        //     Ok(val) => val,
        //     Err(_) => db_path,
        // };

        Ok(Config { jwt_key })
    }
}
