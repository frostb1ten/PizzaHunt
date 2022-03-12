#![allow(non_snake_case)]
#![allow(unused_variables)]
use error_chain::error_chain;
use std::fs;
use std::io::Write;
use std::io::{BufRead};
use std::time::Duration;


error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting!");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    for line in std::fs::read("./hosts.txt").expect("Could not read file").lines() {
        if let Ok(ip) = line {
            let website = ip.replace("Bugbounty","RustScan\"Bugbounty");
            println!("{}", website);
            let res = client
                .get(&website)
                .timeout(Duration::from_secs(5))
                .send();
            let res = match res.await {
                Ok(v) => v,
                Err(_) => {
                    continue
                },
            };
            if res.status() == 200 {
                let body = res.text().await?;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open("./analysis/live_sites.txt")
                    .unwrap();
                write!(file, "{}\n", website)?;
                if body.contains("RustScan\"Bugbounty") {
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
