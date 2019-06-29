#![feature(proc_macro_hygiene, decl_macro)]
extern crate serde;
extern crate serde_derive;
extern crate clap;
#[macro_use] extern crate slog;
extern crate slog_term;
extern crate slog_async;
extern crate rand;
extern crate data_encoding;
extern crate crypto;
#[macro_use] extern crate rocket;
#[macro_use] extern crate lazy_static;
extern crate regex;

use std::collections::HashMap;
use serde_derive::{Serialize, Deserialize};
use clap::{Arg, ArgMatches, SubCommand};
use std::fs::{OpenOptions, read_to_string, write};
use std::io::BufWriter;
use rand::Rng;
use rand::distributions::Alphanumeric;
use data_encoding::{BASE32, BASE64};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use slog::Drain;
use rusqlite::{Connection, NO_PARAMS};
use uuid::Uuid;
use qrcode::QrCode;
use image::{ png, Luma, ColorType };
use rocket_contrib::templates::Template;
use regex::Regex;

static HOME_URL: &'static str = "http://localhost:8000";
static AUTH_TYPE: &'static str = "totp";
static ISSUER_NAME: &'static str = "VwbLab";

lazy_static! { static ref CLEAN_PATTERN: Regex = Regex::new("[^a-zA-Z0-9-_]+").unwrap(); }

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
    let str = read_to_string("cfr.cfg").map_err(|_| "Error opening config")?;
    let config: Config = toml::from_str(&str).map_err(|_| "Error parsing config")?;
    Ok(config)
}

fn write_config(config: Config) {
    match write("cfr.cfg", toml::to_string(&config).unwrap()) {
        Err(err) => println!("ERR: {:?}", err),
        _ => println!("OK")
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

fn info_to_link(
    qr_type: &str,
    qr_issuer: &str,
    qr_account: &str,
    qr_secret: &str) -> String {
    let link = format!(
        "otpauth://{}/{}:{}?secret={}&issuer={}",
        qr_type,
        qr_issuer,
        qr_account,
        qr_secret,
        qr_issuer);
    link
}

#[get("/invite/<account>")]
fn w_invite(account: String) -> Template {
    let clean_account = CLEAN_PATTERN.replace(&account, "").to_string();

    let conn = Connection::open("./data/invites.db").unwrap();

    // Create db if necessary
    conn.execute("CREATE TABLE IF NOT EXISTS invitees (
        id INTEGER PRIMARY KEY,
        account TEXT,
        token TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP,
        used BOOLEAN DEFAULT 0)", NO_PARAMS).unwrap();
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_account on invitees(account)",
        NO_PARAMS).unwrap();
    // Purge old invites
    conn.execute("DELETE FROM invitees WHERE (created <= datetime('now', '-10 days'))",
        NO_PARAMS).unwrap();
    let token = Uuid::new_v4().to_string();
    conn.execute("INSERT OR REPLACE INTO invitees (account, token) VALUES (?, ?)",
        &[&clean_account, &token]).unwrap();

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
    let clean_token = CLEAN_PATTERN.replace(&token, "").to_string();

    let mut context = HashMap::new();

    let conn = Connection::open("./data/invites.db").unwrap();
    match conn.query_row::<String, _, _>(
        "SELECT account FROM invitees WHERE token=? AND used=0",
        &[&clean_token],
        |row| row.get(0)
    ) {
        Err(_) => {
            // TODO: Log
            context.insert("ErrorMsg", "This invite does not exist and this transaction was logged.".to_string());
            Template::render("error", &context)
        },
        Ok(account) => {
            let config: Config = read_config().unwrap();

            let info = config.users.iter().filter(
                |&user| user.name == account ).filter(
                |&user| match user.otpsecret {
                    Some(ref _otpsecret) => true,
                    None => false
                }).collect::<Vec<&Users>>();
            if info.is_empty() {
                context.insert("ErrorMsg", "There is no secret available for this user name.".to_string());
                Template::render("error", &context)
            }
            else {
                let secret = info[0].otpsecret.as_ref().unwrap();
                let code = QrCode::new(
                    info_to_link(
                        AUTH_TYPE,
                        ISSUER_NAME,
                        &account,
                        secret
                    )).unwrap();
                let image = code.render::<Luma<u8>>().build();
                let mut s = String::new();
                // Note to self:
                // This is one way to allow myself to borrow the string's content again.
                // If I did not create a new scope, we would have:
                // Encoder -(owns)-> fout -(owns)-> s buffer.
                // I hope I learn how to do this better.
                {
                    let fout = &mut BufWriter::new(unsafe { s.as_mut_vec() });
                    png::PNGEncoder::new(fout).encode(&image, image.width(), image.height(), ColorType::Gray(8)).unwrap();
                }
                let enc_img = BASE64.encode(unsafe { s.as_bytes_mut() });

                conn.execute("UPDATE invitees SET used=1 WHERE token=?",
                             &[&clean_token]).unwrap();

                context.insert("Img", enc_img);
                Template::render("onboardonce", &context)
            }
        }
    }
}

fn run_server(_: &ArgMatches, parent_logger: &slog::Logger ) {
    let _log = parent_logger.new(o!("command" => "secret"));

    rocket::ignite()
        .mount("/", routes![w_invite, w_onboard, w_onboardonce])
        .attach(Template::fairing())
        .launch();
}

fn encode_user_secret(matches: &ArgMatches, parent_logger: &slog::Logger ) {
    let _log = parent_logger.new(o!("command" => "secret"));
    let enc_otp = BASE32.encode(random_string(10).as_bytes());

    if let Some(account) = matches.value_of("account") {
        debug!(_log, "encoding_secret"; "account" => account);
        match read_config() {
            Err(_) => {
                debug!(_log, "error_reading_config");
                println!("Error reading config");
            },
            Ok(config) => {
                write_config(patch_user_secret(config, account, &enc_otp));
            }
        }
    }
    else {
        debug!(_log, "encoding_secret");
        println!("Here is a possible configuration for a LDAP TOTP user:");
        println!("  otpsecret = {}", enc_otp);
    }
}

fn encode_user_password(matches: &ArgMatches, parent_logger: &slog::Logger ) {
    let _log = parent_logger.new(o!("command" => "pass"));
    let pass = matches.value_of("password").unwrap();
    let mut sha = Sha256::new();
    sha.input_str(pass);
    let enc_pass = sha.result_str();

    if let Some(account) = matches.value_of("account") {
        debug!(_log, "encoding_pass"; "account" => account);
        match read_config() {
            Err(_) => {
                debug!(_log, "error_reading_config");
                println!("Error reading config");
            },
            Ok(config) => {
                write_config(patch_user_pass(config, account, &enc_pass));
            }
        }
    }
    else {
        debug!(_log, "encoding_pass");
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

    let _log = slog::Logger::root(
        slog_async::Async::new(
                slog_term::FullFormat::new(
                        slog_term::PlainDecorator::new(file)
                    ).build().fuse()
            ).build().fuse(),
        o!()
    );

    debug!(_log, "main()");

    let matches = clap::App::new("glauth thingy")
        .version("0.1.0")
        .author("Chris F Ravenscroft <chris@voilaweb.com>")
        .about("Generate QR Codes etc")
        .subcommand(SubCommand::with_name("serve")
                .about("Run web server")
        )
        .subcommand(SubCommand::with_name("secret")
                .about("Display or set a secret config string")
                .arg(Arg::with_name("account")
                        .value_name("account")
                        .short("a")
                        .long("account")
                        .help("Set account's secret in config file"))
        )
        .subcommand(SubCommand::with_name("pass")
                .about("Display or set a password config string")
                .arg(Arg::with_name("account")
                        .value_name("account")
                        .short("a")
                        .long("account")
                        .help("Set account's password in config file"))
                .arg(Arg::with_name("password")
                        .value_name("password")
                        .short("p")
                        .long("password")
                        .required(true)
                        .help("Desired password"))
        )
        .get_matches();

    match matches.subcommand() {
        ("serve", Some(m)) => run_server(m, &_log),
        ("secret", Some(m)) => encode_user_secret(m, &_log),
        ("pass", Some(m)) => encode_user_password(m, &_log),
        (_,_) => println!("Try 'help'"),
    }

    debug!(_log, "the end");
}
