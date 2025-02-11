use std::io::stdin;
use std::process::{Command, Stdio};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::Encodable2718;
use alloy::hex::{FromHex, ToHexExt};
use alloy::network::TxSignerSync;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{bail, Context, Result};
use bip32::{ChildNumber, DerivationPath, Mnemonic, Seed, XPrv};
use clap::Parser;
use serde::Deserialize;
use signing::sign_data;
use ur::{decode_sign_request, encoded_signature};

pub mod qr;
pub mod signing;
pub mod ur;

#[derive(Deserialize, Debug, Clone)]
struct Config {
    /// A command to get the BIP39 mnemonic phrase or seed
    /// ex. keepassxc-cli show -s -a Password Passwords.kdbx test
    seed_cmd: String,
}

/// A simple offline ETH transaction signer
#[derive(Parser)]
struct Cli {
    /// The EIP1559 json string as hex (created by eth_tx_create)
    input: Option<String>,
}

fn from_eth_tx_create(input: String) -> Result<()> {
    let tx_bytes = <Vec<u8>>::from_hex(input.trim()).context("converting tx json hex to bytes")?;
    let mut tx: TxEip1559 = serde_json::from_slice(&tx_bytes)?;

    println!("Paste private key in hex:");
    let mut pk = String::new();
    stdin().read_line(&mut pk)?;
    let signer = pk.trim().parse::<PrivateKeySigner>()?;

    println!("Signing with address: {}", signer.address());
    println!("Signing tx: {}", serde_json::to_string_pretty(&tx)?);
    let signature = signer.sign_transaction_sync(&mut tx)?;
    let signed_tx = tx.into_signed(signature);
    let tx_envelope = TxEnvelope::from(signed_tx);
    let mut encoded_tx = vec![];
    tx_envelope.encode_2718(&mut encoded_tx);
    println!(
        "Signed transaction: {}",
        serde_json::to_string_pretty(&tx_envelope)?
    );
    let tx_hex = encoded_tx.encode_hex();
    println!("Raw RLP-encoded transaction: {tx_hex}");
    let qr = qr::data_to_qr(tx_hex)?;
    println!("{}", qr);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(input) = cli.input {
        from_eth_tx_create(input)?;
        return Ok(());
    }

    let Some(config_path) = dirs::config_dir().map(|mut p| {
        p.push("eth_tools/config.toml");
        p
    }) else {
        bail!("~/.config/ dir not found")
    };

    if !std::fs::exists(&config_path)? {
        bail!("Warning: config {} not found.", config_path.display());
    }
    let config: Config = toml::from_str(&std::fs::read_to_string(config_path).unwrap_or_default())?;

    let mut tx_input = String::new();
    stdin().read_line(&mut tx_input)?;

    let args: Vec<&str> = config.seed_cmd.split_whitespace().collect();
    let child = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;

    // Check if the command was successful
    let mnemonic_or_seed = if output.status.success() {
        String::from_utf8(output.stdout)?
    } else {
        bail!("Seed cmd failed: {}", String::from_utf8(output.stderr)?);
    };

    let seed = if mnemonic_or_seed.split_whitespace().count() > 0 {
        Mnemonic::new(mnemonic_or_seed.trim(), Default::default())?.to_seed("")
    } else {
        Seed::new(
            <Vec<u8>>::from_hex(mnemonic_or_seed.trim())?
                .try_into()
                .or_else(|_| bail!("Seed length incorrect"))?,
        )
    };

    let sign_req = decode_sign_request(&tx_input)?;

    let derivation_path = sign_req.get_derivation_path().get_components().iter().fold(
        DerivationPath::default(),
        |mut acc, c| {
            acc.push(
                ChildNumber::new(c.get_index().unwrap(), c.is_hardened())
                    .expect("Bad derivation path component"),
            );
            acc
        },
    );

    let xpriv = XPrv::derive_from_path(seed, &derivation_path)?;
    let pk = xpriv.private_key().to_owned();

    let sig = sign_data(pk, &sign_req.get_sign_data())?
        .as_bytes()
        .to_vec();

    let sig_res = encoded_signature(sig)?;

    println!("{}", qr::data_to_qr(sig_res)?);

    Ok(())
}
