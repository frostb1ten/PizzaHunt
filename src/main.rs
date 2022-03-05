use error_chain::error_chain;
use std::fs::File;
use std::fs;
use std::io::Write;
use std::io::{self, BufRead};
use std::path::Path;
extern crate url;

error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting!");
    if let Ok(lines) = read_lines("./hosts.txt") {
        for line in lines {
            if let Ok(ip) = line {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?;
                let website = ip.replace("Bugbounty","RustScan\"Bugbounty");
                let res = client
                    .get(website.clone())
                    .send()
                    .await;
                let res = match res {
                    Ok(v) => v,
                    Err(_err) => continue,
                };
                if res.status() == 200 {
                    let body = res.text().await?;
                    if body.contains("RustScan\"bugbounty") {
                        let mut file = fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("output.txt")
                            .unwrap();
                        write!(file, "{}", website)?;
                        println!("XSS likely in (double quote) {}", website);
                    }
                    let website2 = ip.replace("Bugbounty","RustScan\'Bugbounty");
                    let _res = client
                        .get(website2.clone())
                        .send()
                        .await?;
                    if body.contains("RustScan\'bugbounty") {
                        let mut file = fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("XSSSingle.txt")
                            .unwrap();
                        write!(file, "{}", website2)?;
                        println!("XSS likely in (Single quote) {}", website);
                    if body.contains("ORA-") {
                        let mut file = fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("OraOutput.txt")
                            .unwrap();
                        write!(file, "{}", website)?;
                        println!("SQLi (Oracle) likely in {}", website)
                        }
                    if body.contains("MySQL") {
                        let mut file = fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open("MysqlOutput.txt")
                            .unwrap();
                        write!(file, "{}", website)?;
                        println!("Found the words MySQL in {}\r\n", website)
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}


