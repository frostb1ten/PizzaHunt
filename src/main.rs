#![allow(non_snake_case)]
#![allow(unused_variables)]

use error_chain::error_chain;
use std::fs;
use std::time::Duration;
use std::env;
use regex::Regex;
use std::str;
use fancy_regex::Regex as OtherRegex;
use std::path::Path;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufRead, BufReader, Write},
};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    println!("Gathering parameters... Please wait.");
    if Path::new("./paramspider.txt").exists() {
        fs::remove_file("./paramspider.txt")?;
    }
    fs::create_dir_all("./analysis")?;
    let args: Vec<String> = env::args().collect();
    let domain = &args[1];
    let u = r"https://web.archive.org/cdx/search/cdx?url=".to_owned() + domain + "/*&output=txt&fl=original&collapse=urlkey&page=/";
    let response = reqwest::get(u).await?;
    let response = response.text().await?;
    let re = Regex::new(r"^.?^.*=").unwrap();
    let re2 = Regex::new(r".jpg|.png.|.js").unwrap();
    for line in response.lines() {
        let lines = line.to_string();
        let replace = OtherRegex::new(r"\=(.*)").unwrap();
        let website = replace.replace_all(&lines, "=PizzaHunt\">Bugbounty").to_string();
        if re.is_match(&website) {
            if !re2.is_match(&website) {
                //Write urls to paramspider.txt
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open("./paramspider.txt")
                    .unwrap();
                write!(file, "{}\n", website)?;
            }
        }
    }
    let file = File::open("./paramspider.txt").expect("file error");
    let reader = BufReader::new(file);

    let lines: BTreeSet<_> = reader
        .lines()
        .map(|l| l.expect("Couldn't read a line"))
        .collect();

    let mut file = File::create("./paramspider.txt").expect("file error");

    for line in lines {
        file.write_all(line.as_bytes())
            .expect("Couldn't write to file");

        file.write_all(b"\n").expect("Couldn't write to file");
    }
    //connect to website
    for line in std::fs::read("./paramspider.txt").expect("Could not read file").lines() {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;
        if let Ok(website) = line {
            let res = client
                .get(&website)
                .timeout(Duration::from_secs(10))
                .send();
            let res = match res.await {
                Ok(v) => v,
                Err(_) => {
                    continue;
                }
            };
            if res.status() == 200 {
                println!("CONNECTED: {}", &website);
                let body = res.text().await?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open("./analysis/live_sites.txt")
                    .unwrap();
                write!(file, "{}\n", website)?;
                if body.contains("PizzaHunt\">Bugbounty") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/XSS.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("XSS likely in (double quote) {}", website);
                }
                if website.contains("redirect") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/redirects.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if website.contains("WFSServer") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/WFSServer.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if website.contains(".pl") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/Perl.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if website.contains(".cgi") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/cgi.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if body.contains("Error") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/error.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if body.contains("<?php") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/phpsource.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if website.contains("-bin") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/bins.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                }
                if body.contains("ORA-") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/OraOutput.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("SQLi (Oracle) likely in {}", website)
                }
                if body.contains("MySQL") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/MysqlOutput.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("Found the words MySQL in {}\r\n", website)
                }
            }
        }
    }
    Ok(())
}
