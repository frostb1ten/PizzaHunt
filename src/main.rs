#![allow(non_snake_case)]
#![allow(unused_variables)]

extern crate core;

use error_chain::error_chain;
use regex::Regex;
use fancy_regex::Regex as OtherRegex;
use std::{
    fs,
    time::Duration,
    str,
    collections::BTreeSet,
    fs::File,
    path::Path,
    env::args,
    io::{BufRead, BufReader, Write},
};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
    }
}

fn main() -> Result<()> {
    if Path::new("./paramspider.txt").exists() {
        fs::remove_file("./paramspider.txt").expect("Failed to remove paramspider.txt");
    }
    fs::create_dir_all("./analysis").expect("Failed to create the directory analysis");
    let args: Vec<String> = args().collect();
    if args[1] == "-s" {
        let domain = &args[2];
        leconnect(domain.to_string());
    }
    if args[1] == "-l" {
        let file = &args[2];
        let file = File::open(file)?;
        let mut reader = BufReader::new(file);
        let mut buf = vec![];

        while let Ok(_) = reader.read_until(b'\n', &mut buf) {
            if buf.is_empty() {
                break;
            }
            let line = String::from_utf8_lossy(&buf);
            leconnect(line.to_string());
            buf.clear();
        }
        return Ok(());
    }
    Ok(())
}

#[tokio::main]
async fn leconnect(domain: String) -> Result<()> {
    println!("Gathering parameters... Please wait.");
    let u = r"https://web.archive.org/cdx/search/cdx?url=".to_owned() + &domain + "/*&output=txt&fl=original&collapse=urlkey&page=/";
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0")
        .build()?;
    let response = client
        .get(&u)
        .send().await.expect("Failed to grab parameters")
        .text().await.expect("Failed to grab parameters");
    let re = Regex::new(r"^.?^.*=").unwrap();
    let re2 = Regex::new(r".jpg|.png|.js").unwrap();
    for line in response.lines() {
        let lines = line.to_string();
        let replace = OtherRegex::new(r"\=(.*)").unwrap();
        let website = replace.replace_all(&lines, "=PizzaHunt\">Bugbounty{{3*3}}").to_string();
        if re.is_match(&website) {
            if !re2.is_match(&website) {
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
    let file = File::open("./paramspider.txt").map_err(|_| "Please specify a valid file name")?;
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

    for line in fs::read("./paramspider.txt").expect("Could not read file").lines() {
        if let Ok(website) = line {
            let res = client
                .get(&website)
                .timeout(Duration::from_secs(5))
                .send();
            let res = match res.await {
                Ok(v) => v,
                Err(_) => {
                    continue;
                }
            };
            if res.status() != 404 {
                println!("{} : {}", res.status(), website);
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
                if body.contains("Bugbounty9") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/SSTI.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("SSTI likely in {}", website);
                }
                let redirect = ["next=",
                    "url=", "target=", "rurl=", "dest=", "destination=", "redir=", "redirect_uri=", "redirect_url=", "redirect=", "cgi-bin/redirect.cgi", "view= ", "loginto= ", "image_url= ", "go= ", "return= ", "returnTo= ", "return_to= ", "checkout_url= ", "continue= ", "return_path= ", "returnUrl="];
                if redirect.iter().any(|e| website.contains(e)) {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/redirects.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("Possible open redirect {}", website);
                }
                if website.contains("WFSServer") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/WFSServer.txt").unwrap();
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
                        .open("./analysis/error.txt").unwrap();
                    write!(file, "{}\n", website)?;
                }
                if body.contains(" <?php") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/phpsource.txt").unwrap();
                    write!(file, "{}\n", website)?;
                }
                if website.contains(" - bin") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/bins.txt").unwrap();
                    write!(file, "{}\n", website)?;
                }
                if body.contains("exec($_GET") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/wtflol.txt").unwrap();
                    println!("Param fed into exec at {}", website);
                    write!(file, "{}\n", website)?;
                }
                if body.contains("eval($_GET") {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/eval.txt").unwrap();
                    println!("Param fed into eval fn at {}", website);
                    write!(file, "{}\n", website)?;
                }
                let sql_errors = ["SQL syntax", "MariaDB server version", "syntax to use near", "SyntaxError", "unterminated quoted string", "Microsoft Access Driver", "Access Database Engine", "ORA-", "Oracle error", "Microsoft OLE DB", "CLI Driver", "DB2 SQL error", "SQLite/JDBCDriver", "System.Data.SQLite.SQLiteException", "OLE DB", "odbc_"];
                if sql_errors.iter().any(|e| body.contains(e)) {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .append(true)
                        .create(true)
                        .open("./analysis/MysqlOutput.txt")
                        .unwrap();
                    write!(file, "{}\n", website)?;
                    println!("SQL Error found in {}\r\n", website)
                }
            }
        }
    }
    Ok(())
}
