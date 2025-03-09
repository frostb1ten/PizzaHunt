#![allow(non_snake_case)]
#![allow(unused_variables)]

use error_chain::error_chain;
use regex::Regex;
use fancy_regex::Regex as OtherRegex;
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    fs::create_dir_all("./analysis").expect("Failed to create the directory analysis");

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!(
            "Usage: PizzaHunt.exe -s <domain> OR -l <file>\n\
            Example: PizzaHunt.exe -s example.com\n\
            Example: PizzaHunt.exe -l domains.txt"
        );
        return Ok(());
    }

    let domains = match args[1].as_str() {
        "-s" => {
            if args.len() < 3 {
                eprintln!("Error: Missing domain after '-s'");
                return Ok(());
            }
            vec![args[2].clone()]
        }
        "-l" => {
            if args.len() < 3 {
                eprintln!("Error: Missing file name after '-l'");
                return Ok(());
            }
            let file = File::open(&args[2])?;
            BufReader::new(file)
                .lines()
                .map(|l| l.expect("Couldn't read a line"))
                .collect()
        }
        _ => {
            eprintln!("Invalid option. Use -s for a single domain or -l for a list of domains.");
            return Ok(());
        }
    };

    for domain in domains {
        if let Err(e) = process_domain(domain).await {
            eprintln!("Error processing domain: {}", e);
        }
    }

    Ok(())
}

async fn process_domain(domain: String) -> Result<()> {
    let urls = gather_urls(&domain).await?;
    let deduplicated_urls = deduplicate_urls(urls);
    analyze_urls(deduplicated_urls).await
}

async fn gather_urls(domain: &str) -> Result<Vec<String>> {
    if Path::new("./paramspider.txt").exists() {
        fs::remove_file("./paramspider.txt").expect("Failed to remove paramspider.txt");
    }

    println!("Gathering parameters for {}... Please wait.", domain);

    let wayback_url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}/*&output=txt&fl=original&collapse=urlkey&page=/",
        domain
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0")
        .build()?;

    let response = client.get(&wayback_url).send().await?.text().await?;
    let re = Regex::new(r"^.?^.*=").unwrap();
    let re2 = Regex::new(r"\b(\.jpg|\.png|\.js)\b").unwrap();

    let mut urls = Vec::new();
    for line in response.lines() {
        let lines = line.to_string();
        let replace = OtherRegex::new(r"\=(.*)").unwrap();
        let website = replace
            .replace_all(&lines, "=PizzaHunt\">Bugbounty{{3*3}}")
            .to_string();

        if re.is_match(&website) && !re2.is_match(&website) {
            urls.push(website);
        }
    }
    Ok(urls)
}

fn deduplicate_urls(urls: Vec<String>) -> Vec<String> {
    let unique_urls: BTreeSet<_> = urls.into_iter().collect();
    unique_urls.into_iter().collect()
}

async fn analyze_urls(urls: Vec<String>) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0")
        .build()?;

    let mut live_sites = BufWriter::new(File::create("./analysis/live_sites.txt")?);
    let mut xss = BufWriter::new(File::create("./analysis/XSS.txt")?);
    let mut ssti = BufWriter::new(File::create("./analysis/SSTI.txt")?);
    let mut redirects = BufWriter::new(File::create("./analysis/redirects.txt")?);
    let mut mysql_errors = BufWriter::new(File::create("./analysis/MysqlOutput.txt")?);
    let mut wfserver = BufWriter::new(File::create("./analysis/WFSServer.txt")?);
    let mut perl = BufWriter::new(File::create("./analysis/Perl.txt")?);
    let mut cgi = BufWriter::new(File::create("./analysis/cgi.txt")?);
    let mut errors = BufWriter::new(File::create("./analysis/error.txt")?);
    let mut php_source = BufWriter::new(File::create("./analysis/phpsource.txt")?);
    let mut binaries = BufWriter::new(File::create("./analysis/bins.txt")?);
    let mut exec = BufWriter::new(File::create("./analysis/wtflol.txt")?);
    let mut eval = BufWriter::new(File::create("./analysis/eval.txt")?);

    for website in urls {
        let res = client.get(&website).send().await;
        let res = match res {
            Ok(v) => v,
            Err(_) => continue,
        };

        if res.status() == 404 {
            continue;
        }

        let body = res.text().await?;
        writeln!(live_sites, "{}", website)?;

        if body.contains("PizzaHunt\">Bugbounty") {
            writeln!(xss, "{}", website)?;
            println!("XSS likely in {}", website);
        }

        if body.contains("Bugbounty9") {
            writeln!(ssti, "{}", website)?;
            println!("SSTI likely in {}", website);
        }

        let redirect_params = [
            "next=", "url=", "target=", "rurl=", "dest=", "destination=", "redir=",
            "redirect_uri=", "redirect_url=", "redirect=", "cgi-bin/redirect.cgi",
            "view=", "loginto=", "image_url=", "go=", "return=", "returnTo=", "return_to=",
            "checkout_url=", "continue=", "return_path=", "returnUrl="
        ];

        if redirect_params.iter().any(|&e| website.contains(e)) {
            writeln!(redirects, "{}", website)?;
            println!("Possible open redirect {}", website);
        }

        if website.contains(".pl") {
            writeln!(perl, "{}", website)?;
        }

        if website.contains(".cgi") {
            writeln!(cgi, "{}", website)?;
        }

        if body.contains("Error") {
            writeln!(errors, "{}", website)?;
        }

        if body.contains("<?php") {
            writeln!(php_source, "{}", website)?;
        }

        if website.contains("-bin") {
            writeln!(binaries, "{}", website)?;
        }

        if body.contains("exec($_GET") || body.contains("exec($_POST") {
            writeln!(exec, "{}", website)?;
            println!("Potential command execution vulnerability at {}", website);
        }
        
        if body.contains("eval($_GET") || body.contains("eval($_POST") {
            writeln!(eval, "{}", website)?;
            println!("Potential eval-based vulnerability at {}", website);
        }

        let sql_errors = [
            "SQL syntax", "MariaDB server version", "syntax to use near", "SyntaxError",
            "unterminated quoted string", "Microsoft Access Driver", "Access Database Engine",
            "ORA-", "Oracle error", "Microsoft OLE DB", "CLI Driver", "DB2 SQL error",
            "SQLite/JDBCDriver", "System.Data.SQLite.SQLiteException", "OLE DB", "odbc_"
        ];

        if sql_errors.iter().any(|e| body.contains(e)) {
            writeln!(mysql_errors, "{}", website)?;
            println!("SQL Error found in {}", website);
        }
    }

    Ok(())
}
