#![allow(non_snake_case)]

use anyhow::Result;
use regex::Regex;
use colored::*;

use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

#[tokio::main]
async fn main() -> Result<()> {
    fs::create_dir_all("./analysis")?;

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "Usage: PizzaHunt.exe -s <domain> OR -l <file> [--proxy <proxy_url>]\n\
             Example: PizzaHunt.exe -s example.com\n \
             Example: PizzaHunt.exe -l domains.txt\n \
             Example: PizzaHunt.exe -s example.com --proxy http://127.0.0.1:8080"
        );
        return Ok(());
    }

    let mut proxy_url = None;
    let mut domains = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-s" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing domain after '-s'");
                    return Ok(());
                }
                domains.push(args[i + 1].clone());
                i += 1;
            }
            "-l" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing file after '-l'");
                    return Ok(());
                }
                let file = File::open(&args[i + 1])?;
                domains.extend(BufReader::new(file).lines().filter_map(|line| line.ok()));
                i += 1;
            }
            "--proxy" => {
                if i + 1 >= args.len() {
                    eprintln!("Missing proxy URL after '--proxy'");
                    return Ok(());
                }
                proxy_url = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {
                eprintln!("Invalid option: {}", args[i]);
                return Ok(());
            }
        }
        i += 1;
    }

    for domain in domains {
        if let Err(e) = process_domain(domain, proxy_url.clone()).await {
            eprintln!("Error processing domain: {}", e);
        }
    }

    Ok(())
}

fn ensure_https(url: String) -> String {
    if url.starts_with("http://") {
        url.replacen("http://", "https://", 1)
    } else if !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url
    }
}

async fn process_domain(domain: String, proxy_url: Option<String>) -> Result<()> {
    let urls = gather_urls(&domain).await?;
    let deduped = deduplicate_urls(urls).into_iter().map(ensure_https).collect();
    analyze_urls(deduped, proxy_url).await
}

async fn gather_urls(domain: &str) -> Result<Vec<String>> {
    if Path::new("./paramspider.txt").exists() {
        fs::remove_file("./paramspider.txt")?;
    }

    println!("Gathering parameters for {}...", domain);

    let wayback_url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}/*&output=txt&fl=original&collapse=urlkey&page=/",
        domain
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0")
        .build()?;

    let response = client.get(&wayback_url).send().await?.text().await?;
    let param_regex = Regex::new(r".+=.*").unwrap();
    let static_regex = Regex::new(r"\.(jpg|png|js)$").unwrap();
    let replace_regex = Regex::new(r"=(.*)").unwrap();

    let mut urls = Vec::new();
    for line in response.lines() {
        let modified = replace_regex.replace_all(line, "=PizzaHunt\">Bugbounty{{3*3}}").to_string();
        if param_regex.is_match(&modified) && !static_regex.is_match(&modified) {
            urls.push(modified);
        }
    }
    Ok(urls)
}

fn deduplicate_urls(urls: Vec<String>) -> Vec<String> {
    BTreeSet::from_iter(urls).into_iter().collect()
}

async fn analyze_urls(urls: Vec<String>, proxy_url: Option<String>) -> Result<()> {
    let client_builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0");

    let client = if let Some(proxy) = proxy_url {
        client_builder.proxy(reqwest::Proxy::all(&proxy)?).build()?
    } else {
        client_builder.build()?
    };

    let mut writers = [
        ("live_sites.txt", None),
        ("XSS.txt", Some("PizzaHunt\">Bugbounty")),
        ("SSTI.txt", Some("Bugbounty9")),
        ("redirects.txt", None),
        ("MysqlOutput.txt", None),
        ("Perl.txt", Some(".pl")),
        ("cgi.txt", Some(".cgi")),
        ("error.txt", Some("Error")),
        ("phpsource.txt", Some("<?php")),
        ("bins.txt", Some("-bin")),
        ("wtflol.txt", Some("exec($_GET")),
        ("eval.txt", Some("eval($_GET")),
    ].iter().map(|(f, _)| {
        BufWriter::new(OpenOptions::new().create(true).append(true).open(format!("./analysis/{}", f)).unwrap())
    }).collect::<Vec<_>>();

    let sql_errors = [
        "SQL syntax", "MariaDB server version", "syntax to use near", "SyntaxError",
        "unterminated quoted string", "Microsoft Access Driver", "Access Database Engine",
        "ORA-", "Oracle error", "Microsoft OLE DB", "CLI Driver", "DB2 SQL error",
        "SQLite/JDBCDriver", "System.Data.SQLite.SQLiteException", "OLE DB", "odbc_"
    ];

    for url in urls {
        let res = client.get(&url).send().await;
        if let Ok(resp) = res {
            if resp.status() == 404 {
                continue;
            }
            let body = resp.text().await?;
            writeln!(writers[0], "{}", url)?; // live_sites

            if body.contains("PizzaHunt\">Bugbounty") {
                println!("{} {}", "[+] XSS found:".green(), url);
                writeln!(writers[1], "{}", url)?;
            }
            if body.contains("Bugbounty9") {
                println!("{} {}", "[+] SSTI found:".green(), url);
                writeln!(writers[2], "{}", url)?;
            }
            if url.contains(".pl") {
                writeln!(writers[5], "{}", url)?;
            }
            if url.contains(".cgi") {
                writeln!(writers[6], "{}", url)?;
            }
            if body.contains("Error") {
                writeln!(writers[7], "{}", url)?;
            }
            if body.contains("<?php") {
                writeln!(writers[8], "{}", url)?;
            }
            if url.contains("-bin") {
                writeln!(writers[9], "{}", url)?;
            }
            if body.contains("exec($_GET") || body.contains("exec($_POST") {
                println!("{} {}", "[+] exec found:".green(), url);
                writeln!(writers[10], "{}", url)?;
            }
            if body.contains("eval($_GET") || body.contains("eval($_POST") {
                println!("{} {}", "[+] eval found:".green(), url);
                writeln!(writers[11], "{}", url)?;
            }
            if sql_errors.iter().any(|e| body.contains(e)) {
                let mut sql_writer = BufWriter::new(OpenOptions::new().create(true).append(true).open("./analysis/MysqlOutput.txt")?);
                println!("{} {}", "[+] SQL error found:".green(), url);
                writeln!(sql_writer, "{}", url)?;
            }
        }
    }
    Ok(())
}
