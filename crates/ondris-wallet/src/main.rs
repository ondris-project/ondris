mod keystore;

use clap::{Parser, Subcommand};
use ondris_core::{AccountInfo, SubmitTxResponse, Transaction};
use ondris_primitives::Address;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ondris-wallet",
    version,
    about = "CLI wallet for Ondris (testnet)"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new encrypted wallet.
    New {
        #[arg(long)]
        out: PathBuf,
        /// If omitted, the password is prompted for interactively.
        #[arg(long)]
        password: Option<String>,
    },
    /// Shows an existing wallet's address (no password needed).
    Address {
        #[arg(long)]
        wallet: PathBuf,
    },
    /// Queries the node for a wallet's balance and nonce.
    Balance {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        node: String,
    },
    /// Signs and sends a transaction via the node.
    Send {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        password: Option<String>,
        /// Recipient address (ondr...).
        #[arg(long)]
        to: String,
        /// Amount in smallest units (1 ONDR = 100,000,000 units).
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        node: String,
    },
}

fn get_password(provided: Option<String>) -> anyhow::Result<String> {
    match provided {
        Some(p) => Ok(p),
        None => Ok(rpassword::prompt_password("Wallet password: ")?),
    }
}

fn fetch_account(
    client: &reqwest::blocking::Client,
    node: &str,
    address: &str,
) -> anyhow::Result<AccountInfo> {
    let info = client
        .get(format!("{node}/account/{address}"))
        .send()?
        .error_for_status()?
        .json()?;
    Ok(info)
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    match args.command {
        Command::New { out, password } => {
            let password = get_password(password)?;
            anyhow::ensure!(
                password.len() >= 8,
                "the password must be at least 8 characters long"
            );
            let (ks, keypair) = keystore::create(&password)?;
            keystore::save(&out, &ks)?;
            println!("Wallet created: {}", out.display());
            println!("Address       : {}", keypair.address());
            println!("⚠ Back up this file AND your password: without both, the funds are lost.");
        }
        Command::Address { wallet } => {
            let ks = keystore::load(&wallet)?;
            println!("{}", ks.address);
        }
        Command::Balance { wallet, node } => {
            let ks = keystore::load(&wallet)?;
            let client = reqwest::blocking::Client::new();
            let info = fetch_account(&client, &node, &ks.address)?;
            println!("Address: {}", info.address);
            println!("Balance: {} (smallest unit)", info.balance);
            println!("Nonce  : {}", info.nonce);
        }
        Command::Send {
            wallet,
            password,
            to,
            amount,
            fee,
            node,
        } => {
            let ks = keystore::load(&wallet)?;
            let password = get_password(password)?;
            let keypair = keystore::unlock(&ks, &password)?;

            let client = reqwest::blocking::Client::new();
            let info = fetch_account(&client, &node, &ks.address)?;
            let to_addr: Address = to.parse()?;

            let mut tx =
                Transaction::new_unsigned(keypair.public(), to_addr, amount, fee, info.nonce);
            tx.sign(&keypair);

            let resp: SubmitTxResponse = client
                .post(format!("{node}/tx/submit"))
                .json(&tx)
                .send()?
                .error_for_status()?
                .json()?;
            println!("Transaction sent: {}", resp.tx_hash);
        }
    }

    Ok(())
}
