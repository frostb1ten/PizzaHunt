<h1 align="center">PizzaHunt</h1> <p align="center">A tool to out pizza the hunt.</p>

<p align="center">
  <img width="200" src="https://user-images.githubusercontent.com/68353531/158382636-dc504b50-c738-495d-9292-147706085005.png" alt="Material Bread logo">

  
</p>

Scans for indications of an XSS vuln (Double quote escapes) , Oracle SQLi (ORA- in response), filters out url responses containing MySQL, redirect in url and more!

How to compile
```
Install Rust using RustUp from https://rustup.rs/
sudo apt-get install pkg-config libssl-dev
rustup update
git clone https://github.com/frostb1ten/PizzaHunt.git
cd PizzaHunt
cargo build --release
```

How to run
```
./PizzaHunt DOMAIN.com
```


<h2>Compiled version at https://github.com/frostb1ten/PizzaHunt/releases/</h2>


<h3>PizzaHunt image and naming credit goes to whisp3r :)</h3>
<h3>***This tool is for VDP/Bugbounty usage only. We are not liable for any damages or trouble caused by this scanner.***</h3>
