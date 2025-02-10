use std::collections::HashMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::consensus::constants::ETH_TO_WEI;
use alloy::consensus::TxEip1559;
use alloy::eips::eip2718::EIP1559_TX_TYPE_ID;
use alloy::hex::ToHexExt;
use alloy::network::TransactionBuilder;
use alloy::primitives::{address, Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::transports::http::reqwest::Url;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use image::Luma;
use qrcode::QrCode;
use serde::Deserialize;
use Erc20::Erc20Instance;

const USDC_MAINNET_ADDR: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
const USDC_SEPOLIA_ADDR: Address = address!("94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8");
const USDT_MAINNET_ADDR: Address = address!("dAC17F958D2ee523a2206206994597C13D831ec7");

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Erc20,
    "abi/erc20.json"
);

/// A simple ETH transaction builder
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    token: Token,
}

#[derive(Subcommand)]
enum Token {
    /// Create a native ETH transaction
    Eth {
        #[command(flatten)]
        opts: Eip1559Opts,
    },
    /// Create a USDC ERC20 transaction
    Usdc {
        #[command(flatten)]
        opts: Eip1559Opts,
    },
    /// Create a USDC ERC20 transaction
    UsdcSepolia {
        #[command(flatten)]
        opts: Eip1559Opts,
    },
    /// Create a USDT ERC20 transaction
    Usdt {
        #[command(flatten)]
        opts: Eip1559Opts,
    },
}

impl Token {
    fn default_gas_limit(&self) -> u64 {
        match self {
            Token::Eth { .. } => 21000,
            Token::Usdc { .. } | Token::Usdt { .. } | Token::UsdcSepolia { .. } => 65000,
        }
    }

    fn opts(&self) -> Eip1559Opts {
        match self {
            Token::Eth { opts }
            | Token::Usdc { opts }
            | Token::UsdcSepolia { opts }
            | Token::Usdt { opts } => opts.clone(),
        }
    }

    fn contract_address(&self) -> Option<Address> {
        match self {
            Token::Eth { .. } => None,
            Token::Usdc { .. } => Some(USDC_MAINNET_ADDR),
            Token::UsdcSepolia { .. } => Some(USDC_SEPOLIA_ADDR),
            Token::Usdt { .. } => Some(USDT_MAINNET_ADDR),
        }
    }
}

/// Command-line options for an EIP1559 transaction
#[derive(Args, Clone)]
struct Eip1559Opts {
    /// Source address
    #[arg(short, long, env = "ETH_FROM_ADDRESS")]
    from: Option<Address>,
    /// Destination address
    #[arg(short, long)]
    to: AddressOrAlias,
    /// Amount to send in large denom (ex. ETH)
    #[arg(short, long)]
    amount: f64,
    #[arg(long)]
    gas_limit: Option<u64>,
    #[arg(long)]
    max_fee_per_gas: Option<u128>,
    #[arg(long)]
    max_priority_fee_per_gas: Option<u128>,
}

#[derive(Debug, Clone)]
enum AddressOrAlias {
    /// Parsed Address (hex)
    Address(Address),
    /// Address Book alias
    Alias(String),
}

impl FromStr for AddressOrAlias {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Address::from_str(s)
            .map(AddressOrAlias::Address)
            .unwrap_or_else(|_| AddressOrAlias::Alias(s.into())))
    }
}

#[derive(Debug, Deserialize, Default)]
struct AddressBook {
    my_address: Option<Address>,
    contacts: HashMap<String, Address>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli { token } = Cli::parse();

    let provider =
        ProviderBuilder::new().on_http(Url::parse("https://ethereum-sepolia-rpc.publicnode.com")?);

    let Eip1559Opts {
        from,
        to,
        amount,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    } = token.opts();

    let contract = token
        .contract_address()
        .map(|addr| Erc20Instance::new(addr, provider.clone()));

    let Some(config_path) = dirs::config_dir().map(|mut p| {
        p.push("eth_tools/address_book.toml");
        p
    }) else {
        bail!("~/.config/ dir not found")
    };

    if !std::fs::exists(&config_path)? {
        println!("Warning: config {} not found.", config_path.display());
    }
    let address_book: AddressBook =
        toml::from_str(&std::fs::read_to_string(config_path).unwrap_or_default())?;

    let from = from
        .or(address_book.my_address)
        .context("Provide a source/from address on the command line or config file")?;
    println!("Using source address: {from}");

    let mut to = match to {
        AddressOrAlias::Address(address) => address,
        AddressOrAlias::Alias(alias) => address_book
            .contacts
            .get(&alias)
            .with_context(|| format!("Alias {alias} not found in address book"))?
            .to_owned(),
    };

    let chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(from).await?;
    let fee_estimates = provider.estimate_eip1559_fees(None).await?;
    let max_fee_per_gas = max_fee_per_gas.unwrap_or(fee_estimates.max_fee_per_gas);
    let max_priority_fee_per_gas =
        max_priority_fee_per_gas.unwrap_or(fee_estimates.max_priority_fee_per_gas);

    let (amount, input) = if let Some(contract) = contract {
        to = contract.address().to_owned();
        let decimals = contract.decimals().call().await?._0;
        let multiplier = (10u128.pow(decimals.into())) as f64;
        let amount = amount * multiplier;
        (
            0.0,
            contract
                .transfer(to, U256::from(amount))
                .calldata()
                .to_owned(),
        )
    } else {
        (amount * (ETH_TO_WEI as f64), vec![].into())
    };

    let tx_req = TransactionRequest::default()
        .with_chain_id(chain_id)
        .transaction_type(EIP1559_TX_TYPE_ID)
        .with_to(to)
        .with_nonce(nonce)
        .with_value(U256::from(amount))
        .with_input(input)
        .with_gas_limit(gas_limit.unwrap_or(token.default_gas_limit()))
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee_per_gas(max_priority_fee_per_gas)
        .build_typed_tx();

    let Ok(typed_tx) = tx_req else {
        bail!("Incomplete transaction request {tx_req:?}")
    };

    let tx = typed_tx
        .eip1559()
        .with_context(|| format!("Unexpected transaction: {typed_tx:?}"))?;

    let json_str = serde_json::to_string_pretty(tx)?;
    println!("Unsigned transaction: \n{}", json_str);
    let json_bytes = json_str.as_bytes().encode_hex();
    println!("JSON bytes as hex (to be imported to offline signer):\n{json_bytes}");

    let qr = QrCode::new(json_bytes).unwrap();
    let qr_img = qr.render::<Luma<u8>>().build();
    let img_path = format!(
        "/tmp/tx_{}.png",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    qr_img.save(&img_path).unwrap();
    println!("Open {img_path} for QR code");

    Ok(())
}
