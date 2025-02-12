use std::io::{stdin, stdout, Write};
use std::process::{Command, Output, Stdio};

use alloy::consensus::TxEip1559;
use alloy::hex::{FromHex, ToHexExt};
use alloy::primitives::utils::{format_ether, format_units};
use anyhow::{bail, Context, Result};
use bip32::{ChildNumber, DerivationPath, Mnemonic, Seed, XPrv};
use serde::Deserialize;
use signing::{parse_sign_data, sign_eip1559};
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

fn print_human_readable_tx_info(tx: &TxEip1559) -> Result<()> {
    let TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to,
        value,
        ..
    } = tx;
    println!();
    println!("To address: {}", serde_json::to_string(to)?);
    println!("Amount {} ETH", format_ether(*value));
    println!("Gas Limit: {gas_limit}");
    println!(
        "Max Fee Per Gas: {} GWEI",
        format_units(*max_fee_per_gas, "gwei")?
    );
    println!(
        "Max Priority Fee Per Gas: {} GWEI",
        format_units(*max_priority_fee_per_gas, "gwei")?
    );
    println!("Chain ID: {chain_id}");
    println!("Nonce: {nonce}");
    println!();

    Ok(())
}

fn main() -> Result<()> {
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
    println!(
        "Sign Request for address: {}",
        sign_req
            .get_address()
            .map_or_else(|| String::from("N/A"), |v| v.encode_hex())
    );
    let req_id = sign_req.get_request_id();
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

    let mut tx = parse_sign_data(&sign_req.get_sign_data())?;
    println!(
        "Raw transaction to sign:\n{}",
        serde_json::to_string_pretty(&tx)?
    );

    print_human_readable_tx_info(&tx)?;

    print!("Sign this transaction? (y/N): ");
    stdout().flush()?;

    let mut answer = String::new();
    stdin().read_line(&mut answer)?;
    match answer.to_lowercase().trim() {
        "y" | "yes" => {
            let sig = sign_eip1559(pk, &mut tx)?;
            let sig_res = encoded_signature(req_id, &sig)?;
            println!("{}", qr::data_to_qr(sig_res)?);
        }
        _ => bail!("Signing aborted."),
    }

    Ok(())
}
