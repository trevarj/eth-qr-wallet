use std::io::stdin;
use std::process::{Command, Output, Stdio};

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
    /// A command to run that scans and decodes a QR
    qr_scan_cmd: String,
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

fn parse_command(cmd: &str) -> Result<(&str, Vec<&str>)> {
    let splits: Vec<&str> = cmd.split_whitespace().collect();
    let cmd = splits.first().context("cmd missing exe")?;
    Ok((cmd, splits[1..].to_vec()))
}

fn parse_command_output(output: Output) -> Result<String> {
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?)
    } else {
        bail!("Seed cmd failed: {}", String::from_utf8(output.stderr)?);
    }
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

    let (cmd, args) = parse_command(&config.qr_scan_cmd)?;
    let child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;
    let sign_req = parse_command_output(output)?;

    let (cmd, args) = parse_command(&config.seed_cmd)?;
    let child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()?;
    let output = child.wait_with_output()?;

    let parsed = parse_command_output(output)?;
    let mnemonic_or_seed: Vec<&str> = parsed.split_whitespace().collect();
    println!("Parsing mnemonic or seed...");
    let seed = match mnemonic_or_seed.len() {
        0 => bail!("Empty string parsed from seed cmd"),
        1 => Seed::new(
            <Vec<u8>>::from_hex(mnemonic_or_seed.first().unwrap())
                .context("Invalid hex for seed")?
                .try_into()
                .or_else(|_| bail!("Seed length incorrect"))?,
        ),
        _ => Mnemonic::new(mnemonic_or_seed.join(" "), Default::default())?.to_seed(""),
    };

    let sign_req = decode_sign_request(&sign_req)?;

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
