use alloy::consensus::TxEip1559;
use alloy::network::TxSignerSync;
use alloy::rlp::Decodable;
use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;

pub fn parse_sign_data(tx: &[u8]) -> Result<TxEip1559> {
    Ok(TxEip1559::decode(&mut &tx[1..])?)
}

pub fn sign_eip1559(pk: impl Into<PrivateKeySigner>, tx: &mut TxEip1559) -> Result<[u8; 65]> {
    let signer: PrivateKeySigner = pk.into();
    println!("Signing with address: {}", signer.address());
    let s = signer.sign_transaction_sync(tx)?;
    let mut sig = [0u8; 65];
    sig[..32].copy_from_slice(&s.r().to_be_bytes::<32>());
    sig[32..64].copy_from_slice(&s.s().to_be_bytes::<32>());
    sig[64] = s.v() as u8;
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use alloy::hex::{FromHex, ToHexExt};
    use bip32::{Mnemonic, XPrv};

    use super::*;

    #[test]
    fn can_sign_data() {
        let seed = Mnemonic::new(
            include_str!("../test_mnemonic.txt").trim(),
            Default::default(),
        )
        .unwrap()
        .to_seed("");
        let xpriv = XPrv::derive_from_path(seed, &("m/44'/60'/0'/0/0".parse().unwrap())).unwrap();
        let pk = xpriv.private_key();
        // assert_eq!(
        //     "0365d9b6aa0b9980a79f1575f51b40ec5d9972de8502927f3e64895359cf3448a7",
        //     xpriv.public_key().to_bytes().encode_hex()
        // );
        let data= <Vec<u8>>::from_hex("02f283aa36a7808459682f00851e96c0a3bc82520894cc53351624cd19c4555d6ada86a919134b20746b87038d7ea4c6800080c0").unwrap();
        let mut parsed = parse_sign_data(&data).unwrap();
        let signature = sign_eip1559(pk.to_owned(), &mut parsed).unwrap();
        dbg!(signature.encode_hex());
    }
}
