#[derive(Copy, Clone)]
pub struct Erc20Token {
    pub chain_id: u64,
    pub address: &'static str,
    pub decimals: u8,
    pub symbol: &'static str,
}

impl Erc20Token {
    const fn new(chain_id: u64, address: &'static str, decimals: u8, symbol: &'static str) -> Self {
        Self {
            chain_id,
            address,
            decimals,
            symbol,
        }
    }

    pub fn from_addr(addr: &str) -> Option<Erc20Token> {
        TOKENS
            .iter()
            .find(|t| t.address.to_lowercase() == addr.to_lowercase())
            .copied()
    }
}

const TOKENS: [Erc20Token; 3] = [
    Erc20Token::new(
        11155111,
        "0x94a9d9ac8a22534e3faca9f4e7f2e2cf85d5e4c8",
        6,
        "Sepolia USDC",
    ),
    Erc20Token::new(1, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6, "USDC"),
    Erc20Token::new(1, "0xdAC17F958D2ee523a2206206994597C13D831ec7", 6, "USDT"),
];
