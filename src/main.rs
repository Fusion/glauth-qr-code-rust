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

use froop::{Sink, Stream}; // Lightweight but fully synchronous
use std::collections::HashMap;
use serde_derive::{Serialize, Deserialize};
use clap::{Arg, ArgMatches, SubCommand};
use std::fs::{OpenOptions, read_to_string, write};
use std::io::BufWriter;
use std::io::Write;
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

lazy_static! {
    static ref LOG: slog::Logger = slog::Logger::root(
        slog_async::Async::new(
                slog_term::FullFormat::new(
                        slog_term::PlainDecorator::new(
                            OpenOptions::new()
                                .create(true)
                                .write(true)
                                .truncate(true)
                                .open("my.log")
                                .unwrap()
                            )
                    ).build().fuse()
            ).build().fuse(),
        o!()
    );
}

//░░░█▀█░█▀█░▀█▀░█▀▀░█▀▀░░
//░░░█░█░█░█░░█░░█▀▀░▀▀█░░
//░░░▀░▀░▀▀▀░░▀░░▀▀▀░▀▀▀░░

enum NoteCat {
    Debug,
    Warn,
}

enum NoteCtx {
    Log(String),
}

struct NoteData {
    cat: NoteCat,
    content: String,
    ctx: Option<NoteCtx>,
}

lazy_static! { static ref SINK: Sink<NoteData> = Stream::sink(); }

macro_rules! make_note {
    ($cat:expr, $content:expr) => {{
        SINK.update(NoteData{cat: $cat, content: $content.to_string(), ctx: None});
    }};
}

macro_rules! make_note_ctx {
    ($cat:expr, $content:expr, $ctx:expr) => {{
        SINK.update(NoteData{cat: $cat, content: $content.to_string(), ctx: Some($ctx)});
    }};
}

macro_rules! complain {
    ($msg:expr) => {{
        make_note!(NoteCat::Debug, $msg);
        println!("{}", $msg);
    }};
}

//░░░█▀▀░█▀█░█▀█░█▀▀░▀█▀░█▀▀░░
//░░░█░░░█░█░█░█░█▀▀░░█░░█░█░░
//░░░▀▀▀░▀▀▀░▀░▀░▀░░░▀▀▀░▀▀▀░░

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

/*
 * Boxing errors...this allows us to return various error types.
 *
 * This is more helpful to debug our app than using
 * my_operation.map_err(|_| my_test)?;
 */
type WrappedResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn read_config() -> WrappedResult<Config> {
    let str = read_to_string("cfr.cfg")?;
    let config: Config = toml::from_str(&str)?;
    Ok(config)
}


fn write_config(config: Config) -> WrappedResult<()> {
    let str = toml::to_string(&config)?;
    write("cfr.cfg", str)?;
    Ok(())
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
fn w_invite(account: String) -> WrappedResult<Template> {
    let clean_account = CLEAN_PATTERN.replace(&account, "").to_string();

    let conn = Connection::open("./data/invites.db")?;

    // Create db if necessary
    conn.execute("CREATE TABLE IF NOT EXISTS invitees (
        id INTEGER PRIMARY KEY,
        account TEXT,
        token TEXT,
        created DATETIME DEFAULT CURRENT_TIMESTAMP,
        used BOOLEAN DEFAULT 0)", NO_PARAMS)?;
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_account on invitees(account)",
        NO_PARAMS)?;
    // Purge old invites
    conn.execute("DELETE FROM invitees WHERE (created <= datetime('now', '-10 days'))",
        NO_PARAMS)?;
    let token = Uuid::new_v4().to_string();
    conn.execute("INSERT OR REPLACE INTO invitees (account, token) VALUES (?, ?)",
        &[&clean_account, &token])?;

    let mut context = HashMap::new();
    context.insert("Account", clean_account);
    context.insert("Link", format!("{}/onboard/{}", HOME_URL, token));
    Ok(Template::render("invite", &context))
}

#[get("/onboard/<token>")]
fn w_onboard(token: String) -> WrappedResult<Template> {
    let mut context = HashMap::new();
    context.insert("Link", format!("{}/onboardonce/{}", HOME_URL, token));
    Ok(Template::render("onboard", &context))
}

#[get("/onboardonce/<token>")]
fn w_onboardonce(token: String) -> WrappedResult<Template> {
    let clean_token = CLEAN_PATTERN.replace(&token, "").to_string();

    let mut context = HashMap::new();

    let conn = Connection::open("./data/invites.db")?;
    match conn.query_row::<String, _, _>(
        "SELECT account FROM invitees WHERE token=? AND used=0",
        &[&clean_token],
        |row| row.get(0)
    ) {
        Err(_) => {
            // TODO: IP Address
            make_note_ctx!(NoteCat::Warn, "non_existent_invite", NoteCtx::Log("Web-Invite".to_string()));
            context.insert("ErrorMsg", "This invite does not exist and this transaction was logged.".to_string());
            Ok(Template::render("error", &context))
        },
        Ok(account) => {
            let config: Config = read_config()?;

            let info = config.users.iter().filter(
                |&user| user.name == account ).filter(
                |&user| match user.otpsecret {
                    Some(ref _otpsecret) => true,
                    None => false
                }).collect::<Vec<&Users>>();
            if info.is_empty() {
                context.insert("ErrorMsg", "There is no secret available for this user name.".to_string());
                Ok(Template::render("error", &context))
            }
            else {
                let secret = info[0].otpsecret.as_ref().unwrap();
                let code = QrCode::new(
                    info_to_link(
                        AUTH_TYPE,
                        ISSUER_NAME,
                        &account,
                        secret
                    ))?;
                let image = code.render::<Luma<u8>>().build();
                // Note to self:
                // This is one way to allow myself to borrow the string's content again.
                // I hope I learn how to do this better.
                let mut buffer: Vec<u8> = vec![];
                {
                    let fout = &mut BufWriter::new(buffer.by_ref());
                    png::PNGEncoder::new(fout).encode(&image, image.width(), image.height(), ColorType::Gray(8))?;
                }
                let enc_img = BASE64.encode(&buffer);

                conn.execute("UPDATE invitees SET used=1 WHERE token=?",
                             &[&clean_token])?;

                context.insert("Img", enc_img);
                Ok(Template::render("onboardonce", &context))
            }
        }
    }
}



//░░░▀█▀░█▀█░█▀█░░░░░█░░░█▀▀░█░█░█▀▀░█░░░░░█▀▀░█░█░█▀█░█▀▀░▀█▀░▀█▀░█▀█░█▀█░█▀▀░░
//░░░░█░░█░█░█▀▀░▄▄▄░█░░░█▀▀░▀▄▀░█▀▀░█░░░░░█▀▀░█░█░█░█░█░░░░█░░░█░░█░█░█░█░▀▀█░░
//░░░░▀░░▀▀▀░▀░░░░░░░▀▀▀░▀▀▀░░▀░░▀▀▀░▀▀▀░░░▀░░░▀▀▀░▀░▀░▀▀▀░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀▀░░

fn run_server(_: &ArgMatches) {
    let _log = LOG.new(o!("command" => "secret"));

    rocket::ignite()
        .mount("/", routes![w_invite, w_onboard, w_onboardonce])
        .attach(Template::fairing())
        .launch();
}

fn encode_user_secret(matches: &ArgMatches) {
    let enc_otp = BASE32.encode(random_string(10).as_bytes());

    if let Some(account) = matches.value_of("account") {
        // TODO NO logger needs to be created when logging
        make_note!(NoteCat::Debug, format!("encoding_secret for {}", account));
        match read_config() {
            Err(_) => complain!("Error reading config"),
            Ok(config) => {
                match write_config(patch_user_secret(config, account, &enc_otp)) {
                    Ok(_) => (),
                    Err(err) => complain!(err),
                }
            }
        }
    }
    else {
        make_note!(NoteCat::Debug, "encoding_secret");
        println!("Here is a possible configuration for a LDAP TOTP user:");
        println!("  otpsecret = {}", enc_otp);
    }
}

fn encode_user_password(matches: &ArgMatches) {
    // Safe to unwrap because argument was declared as required
    let pass = matches.value_of("password").unwrap();
    let mut sha = Sha256::new();
    sha.input_str(pass);
    let enc_pass = sha.result_str();

    if let Some(account) = matches.value_of("account") {
        make_note!(NoteCat::Debug, "encoding_pass");
        match read_config() {
            Err(_) => complain!("Error reading config"),
            Ok(config) => {
                match write_config(patch_user_pass(config, account, &enc_pass)) {
                    Ok(_) => (),
                    Err(err) => complain!(err),
                }
            }
        }
    }
    else {
        make_note!(NoteCat::Debug, "encoding_pass");
        println!("Here is a possible configuration for a LDAP user:");
        println!("  passsha256 = {}", enc_pass);
    }
}

fn main() {

    // Init Logging
    let stream: Stream<NoteData> = SINK.stream();
    stream.subscribe(|notedata| if let Some(notedata) = notedata {
        match notedata {
            NoteData { cat: NoteCat::Debug, content, ctx: Some(NoteCtx::Log(log)) } =>
                debug!(LOG, "{}:{}", log, content),
            NoteData { cat: NoteCat::Debug, content, ctx: None } =>
                debug!(LOG, "{}", content),
            NoteData { cat: NoteCat::Warn, content, ctx: Some(NoteCtx::Log(log)) } =>
                warn!(LOG, "{}:{}", log, content),
            NoteData { cat: NoteCat::Warn, content, ctx: None } =>
                warn!(LOG, "{}", content),
        }
    });

    make_note!(NoteCat::Debug, "main()");

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
        ("serve", Some(m)) => run_server(m),
        ("secret", Some(m)) => encode_user_secret(m),
        ("pass", Some(m)) => encode_user_password(m),
        (_,_) => println!("Try 'help'"),
    }

    make_note!(NoteCat::Debug, "the end");
}
