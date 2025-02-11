use std::io::stdin;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::Encodable2718;
use alloy::hex::{FromHex, ToHexExt};
use alloy::network::TxSignerSync;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use clap::Parser;

pub mod qr;
pub mod ur;

/// A simple offline ETH transaction signer
#[derive(Parser)]
struct Cli {
    /// The EIP1559 json string as hex (created by eth_tx_create)
    tx: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let tx_bytes = <Vec<u8>>::from_hex(cli.tx.trim()).context("converting tx json hex to bytes")?;
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
