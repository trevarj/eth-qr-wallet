use anyhow::Result;
use bip32::{PublicKey, XPub};
use ur_registry::crypto_coin_info::{CoinType, CryptoCoinInfo, Network};
use ur_registry::crypto_hd_key::CryptoHDKey;
use ur_registry::crypto_key_path::{CryptoKeyPath, PathComponent};
use ur_registry::traits::{RegistryItem, To};

pub fn encoded_xpub(xpub: &XPub, master_fingerprint: [u8; 4]) -> Result<String> {
    let pubkey = xpub.public_key().to_bytes();
    let chain_code = xpub.attrs().chain_code;
    let hd_key = CryptoHDKey::new_extended_key(
        None,
        pubkey.to_vec(),
        Some(chain_code.into()),
        Some(CryptoCoinInfo::new(
            Some(CoinType::Ethereum),
            Some(Network::MainNet),
        )),
        Some(CryptoKeyPath::new(
            vec![
                PathComponent::new(Some(44), true).unwrap(),
                PathComponent::new(Some(60), true).unwrap(),
                PathComponent::new(Some(0), true).unwrap(),
            ],
            Some(master_fingerprint),
            Some(xpub.attrs().depth.into()),
        )),
        Some(CryptoKeyPath::new(
            vec![
                PathComponent::new(Some(0), false).unwrap(),
                PathComponent::new(None, false).unwrap(),
            ],
            None,
            Some(0),
        )),
        Some(xpub.attrs().parent_fingerprint),
        None,
        Some("account.standard".into()),
    );
    Ok(ur::encode(
        #[allow(deprecated)]
        &hd_key.to_bytes()?,
        CryptoHDKey::get_registry_type().get_type(),
    ))
}

#[cfg(test)]
mod tests {
    use bip32::{Mnemonic, Prefix, XPrv};

    use super::*;

    #[test]
    fn can_encode_xpub() {
        // requires 24-word mnemonic in ../test_mnemonic.txt
        let seed = Mnemonic::new(
            include_str!("../test_mnemonic.txt").trim(),
            Default::default(),
        )
        .unwrap()
        .to_seed("");
        let m_xpriv = XPrv::new(&seed).unwrap();
        let m_xpub = m_xpriv.public_key();
        println!("master xpub: {}", m_xpub.to_string(Prefix::XPUB));
        let master_fingerprint = m_xpriv.public_key().fingerprint();
        let xpriv = XPrv::derive_from_path(seed, &("m/44'/60'/0'".parse().unwrap())).unwrap();
        let xpub = xpriv.public_key();
        println!("x pubkey: {}", xpub.to_string(Prefix::XPUB));
        let string = encoded_xpub(&xpub, master_fingerprint).unwrap();
        println!("{string}\n{}", crate::qr::data_to_qr(&string).unwrap());
    }
}
