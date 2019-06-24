#![feature(proc_macro_hygiene, decl_macro)]

use clap::{Arg, ArgMatches, SubCommand};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use data_encoding::{BASE32, BASE64};
use image::{png, ColorType, Luma};
use lazy_static::lazy_static;
use qrcode::QrCode;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use rocket::{get, routes};
use rocket_contrib::templates::Template;
use rusqlite::{Connection, NO_PARAMS};
use serde_derive::{Deserialize, Serialize};
use slog::Drain;
use slog::{debug, o};
use std::collections::HashMap;
use std::fs::{read_to_string, write, OpenOptions};
use uuid::Uuid;

static HOME_URL: &str = "http://localhost:8000";
static AUTH_TYPE: &str = "totp";
static ISSUER_NAME: &str = "VwbLab";

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Config {
    debug: bool,
    syslog: bool,
    ldap: Ldap,
    ldaps: Ldaps,
    backend: Backend,
    users: Vec<Users>,
    groups: Vec<Groups>,
    api: Api,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Ldap {
    enabled: bool,
    listen: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Ldaps {
    enabled: bool,
    listen: String,
    cert: String,
    key: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Backend {
    datastore: String,
    basedn: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Users {
    name: String,
    unixid: u32,
    primarygroup: u32,
    mail: String,
    passsha256: String,
    otpsecret: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Groups {
    name: String,
    unixid: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Api {
    enabled: bool,
    tls: bool,
    listen: String,
    cert: String,
    key: String,
}

fn random_string(size: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect::<String>()
}

fn read_config() -> Result<Config, &'static str> {
    match read_to_string("cfr.cfg") {
        Ok(str) => {
            // How do I make this trait consistent with clean error handling?
            let config: Config = toml::from_str(&str).unwrap();
            Ok(config)
        }
        Err(_) => Err("Error opening config"),
    }
}

fn write_config(config: Config) {
    match write("cfr.cfg", toml::to_string(&config).unwrap()) {
        Err(err) => println!("ERR: {:?}", err),
        _ => println!("OK"),
    }
}

fn patch_user_secret(mut src: Config, account: &str, enc_otp: &str) -> Config {
    for user in src.users.iter_mut() {
        if user.name == account {
            user.otpsecret = Some(enc_otp.to_string());
        }
    }
    src
}

fn patch_user_pass(mut src: Config, account: &str, enc_pass: &str) -> Config {
    for user in src.users.iter_mut() {
        if user.name == account {
            user.passsha256 = enc_pass.to_string();
        }
    }
    src
}

fn info_to_link(qr_type: &str, qr_issuer: &str, qr_account: &str, qr_secret: &str) -> String {
    let link = format!(
        "otpauth://{}/{}:{}?secret={}&issuer={}",
        qr_type, qr_issuer, qr_account, qr_secret, qr_issuer
    );
    link
}

#[get("/invite/<account>")]
fn w_invite(account: String) -> Template {
    lazy_static! {
        static ref CLEAN_PATTERN: Regex = Regex::new("[^a-zA-Z0-9-_]+").unwrap();
    }
    let clean_account = CLEAN_PATTERN.replace(&account, "").to_string();

    let conn = Connection::open("./data/invites.db").unwrap();

    // Create db if necessary
    conn.execute(
        "CREATE TABLE IF NOT EXISTS invitees (
        id INTEGER PRIMARY KEY,
        account TEXT,
        token TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP,
        used BOOLEAN DEFAULT 0)",
        NO_PARAMS,
    )
    .unwrap();
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_account on invitees(account)",
        NO_PARAMS,
    )
    .unwrap();
    // Purge old invites
    conn.execute(
        "DELETE FROM invitees WHERE (created <= datetime('now', '-10 days'))",
        NO_PARAMS,
    )
    .unwrap();
    let token = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT OR REPLACE INTO invitees (account, token) VALUES (?, ?)",
        &[&clean_account, &token],
    )
    .unwrap();

    let mut context = HashMap::new();
    context.insert("Account", clean_account);
    context.insert("Link", format!("{}/onboard/{}", HOME_URL, token));
    Template::render("invite", &context)
}

#[get("/onboard/<token>")]
fn w_onboard(token: String) -> Template {
    let mut context = HashMap::new();
    context.insert("Link", format!("{}/onboardonce/{}", HOME_URL, token));
    Template::render("onboard", &context)
}

#[get("/onboardonce/<token>")]
fn w_onboardonce(token: String) -> Template {
    lazy_static! {
        static ref CLEAN_PATTERN: Regex = Regex::new("[^a-zA-Z0-9-_]+").unwrap();
    }
    let clean_token = CLEAN_PATTERN.replace(&token, "").to_string();

    let mut context = HashMap::new();

    let conn = Connection::open("./data/invites.db").unwrap();
    match conn.query_row::<String, _, _>(
        "SELECT account FROM invitees WHERE token=? AND used=0",
        &[&clean_token],
        |row| row.get(0),
    ) {
        Err(_err) => {
            // TODO: Log
            context.insert(
                "ErrorMsg",
                "This invite does not exist and this transaction was logged.".to_string(),
            );
            Template::render("error", &context)
        }
        Ok(account) => {
            let config: Config = read_config().unwrap();

            let secret = config
                .users
                .iter()
                .filter(|user| user.name == account)
                .find_map(|user| user.otpsecret.as_ref());

            match secret {
                None => {
                    context.insert(
                        "ErrorMsg",
                        "There is no secret available for this user name.".to_string(),
                    );
                    Template::render("error", &context)
                }
                Some(secret) => {
                    let code = QrCode::new(info_to_link(AUTH_TYPE, ISSUER_NAME, &account, secret))
                        .unwrap();
                    let image = code.render::<Luma<u8>>().build();

                    let mut buf = Vec::new();
                    png::PNGEncoder::new(&mut buf)
                        .encode(&image, image.width(), image.height(), ColorType::Gray(8))
                        .unwrap();
                    let enc_img = BASE64.encode(&buf);

                    conn.execute("UPDATE invitees SET used=1 WHERE token=?", &[&clean_token])
                        .unwrap();

                    context.insert("Img", enc_img);
                    Template::render("onboardonce", &context)
                }
            }
        }
    }
}

fn run_server(_: &ArgMatches, parentlogger: &slog::Logger) {
    let _log = parentlogger.new(o!("command" => "secret"));

    rocket::ignite()
        .mount("/", routes![w_invite, w_onboard, w_onboardonce])
        .attach(Template::fairing())
        .launch();
}

fn encode_user_secret(matches: &ArgMatches, parentlogger: &slog::Logger) {
    let log = parentlogger.new(o!("command" => "secret"));
    let enc_otp = BASE32.encode(random_string(10).as_bytes());

    if let Some(account) = matches.value_of("account") {
        debug!(log, "encoding_secret"; "account" => account);
        match read_config() {
            Err(_) => {
                debug!(log, "error_reading_config");
                println!("Error reading config");
            }
            Ok(config) => {
                write_config(patch_user_secret(config, account, &enc_otp));
            }
        }
    } else {
        debug!(log, "encoding_secret");
        println!("Here is a possible configuration for a LDAP TOTP user:");
        println!("  otpsecret = {}", enc_otp);
    }
}

fn encode_user_password(matches: &ArgMatches, parentlogger: &slog::Logger) {
    let log = parentlogger.new(o!("command" => "pass"));
    let pass = matches.value_of("password").unwrap();
    let mut sha = Sha256::new();
    sha.input_str(pass);
    let enc_pass = sha.result_str();

    if let Some(account) = matches.value_of("account") {
        debug!(log, "encoding_pass"; "account" => account);
        match read_config() {
            Err(_) => {
                debug!(log, "error_reading_config");
                println!("Error reading config");
            }
            Ok(config) => {
                write_config(patch_user_pass(config, account, &enc_pass));
            }
        }
    } else {
        debug!(log, "encoding_pass");
        println!("Here is a possible configuration for a LDAP user:");
        println!("  passsha256 = {}", enc_pass);
    }
}

fn main() {
    let log_path = "my.log";
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path)
        .unwrap();

    let log = slog::Logger::root(
        slog_async::Async::new(
            slog_term::FullFormat::new(slog_term::PlainDecorator::new(file))
                .build()
                .fuse(),
        )
        .build()
        .fuse(),
        o!(),
    );

    debug!(log, "main()");

    let matches = clap::App::new("glauth thingy")
        .version("0.1.0")
        .author("Chris F Ravenscroft <chris@voilaweb.com>")
        .about("Generate QR Codes etc")
        .subcommand(SubCommand::with_name("serve").about("Run web server"))
        .subcommand(
            SubCommand::with_name("secret")
                .about("Display or set a secret config string")
                .arg(
                    Arg::with_name("account")
                        .value_name("account")
                        .short("a")
                        .long("account")
                        .help("Set account's secret in config file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("pass")
                .about("Display or set a password config string")
                .arg(
                    Arg::with_name("account")
                        .value_name("account")
                        .short("a")
                        .long("account")
                        .help("Set account's password in config file"),
                )
                .arg(
                    Arg::with_name("password")
                        .value_name("password")
                        .short("p")
                        .long("password")
                        .required(true)
                        .help("Desired password"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("serve", Some(m)) => run_server(m, &log),
        ("secret", Some(m)) => encode_user_secret(m, &log),
        ("pass", Some(m)) => encode_user_password(m, &log),
        (_, _) => println!("Try 'help'"),
    }

    debug!(log, "the end");
}
