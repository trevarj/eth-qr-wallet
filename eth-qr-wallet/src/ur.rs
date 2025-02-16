use anyhow::{bail, Result};
use bip32::{Prefix, PublicKey, Seed, XPrv, XPub};
use ur_registry::crypto_coin_info::{CoinType, CryptoCoinInfo, Network};
use ur_registry::crypto_hd_key::CryptoHDKey;
use ur_registry::crypto_key_path::{CryptoKeyPath, PathComponent};
use ur_registry::ethereum::eth_sign_request::EthSignRequest;
use ur_registry::ethereum::eth_signature::EthSignature;
use ur_registry::traits::{RegistryItem, To};

pub fn export_hd_key(seed: &Seed) -> Result<()> {
    let m_xpriv = XPrv::new(seed).unwrap();
    let m_xpub = m_xpriv.public_key();
    println!("master xpub: {}", m_xpub.to_string(Prefix::XPUB));
    let master_fingerprint = m_xpriv.public_key().fingerprint();
    let xpriv = XPrv::derive_from_path(seed, &("m/44'/60'/0'".parse().unwrap())).unwrap();
    let xpub = xpriv.public_key();
    let ur = encoded_xpub(&xpub, master_fingerprint)?;
    println!("{}", crate::qr::data_to_qr(&ur).unwrap());
    Ok(())
}

fn encoded_xpub(xpub: &XPub, master_fingerprint: [u8; 4]) -> Result<String> {
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

pub fn decode_sign_request(req: &str) -> Result<EthSignRequest> {
    let (_kind, bytes) = ur::decode(&req.trim().to_lowercase())
        .or_else(|e| bail!("unable to decode sign request: {e}"))?;
    Ok(EthSignRequest::try_from(bytes)?)
}

pub fn encoded_signature(req_id: Option<Vec<u8>>, sig: &[u8]) -> Result<String> {
    let eth_sig = EthSignature::new(req_id, sig.to_vec(), Some("offline_wallet".into()));
    Ok(ur::encode(
        #[allow(deprecated)]
        &eth_sig.to_bytes().unwrap(),
        EthSignature::get_registry_type().get_type(),
    )
    .to_uppercase())
}

#[cfg(test)]
mod tests {
    use alloy::hex::{FromHex, ToHexExt};
    use bip32::Mnemonic;

    use super::*;

    /// Export xpubkey for import into metamask
    #[test]
    fn can_encode_xpub() {
        // requires 24-word mnemonic in ../test_mnemonic.txt
        let seed = Mnemonic::new(
            include_str!("../test_mnemonic.txt").trim(),
            Default::default(),
        )
        .unwrap()
        .to_seed("");
        let string = export_hd_key(&seed).unwrap();
    }

    #[test]
    fn can_decode_sign_request() {
        let req =   decode_sign_request("ur:eth-sign-request/oladtpdagdwseyeelewypsfxcmpyoxytoycmprfxwyaohdeeaowzlspkenoslalrhkisdlaelpckmtrtotrflfgmaymwsfgueccmdksncfssgohlimtnlnptcfbwgrcxjyjeltaxlgkboxswlaaelartaxaaaacyaepkenosahtaaddyoeadlecsdwykcsfnykaeykaewkaewkaocyhgzskihtamghsfgueccmdksncfssgohlimtnlnptcfbwgrcxjyjetlbevery").unwrap();
        dbg!(&req);
        dbg!(req.get_sign_data().encode_hex());
    }

    #[test]
    fn can_encode_signature() {
        let sig = <Vec<u8>>::from_hex("e2a8b9fd25a803baf623c7d0102ddb8b92f47ec93fdcdaf0bdd43d2da4d821816ca0f148c43a25655b772eb9dc689bb10c0fcd9ddced780ab00a8384442f94fb1c").unwrap();
        let string = encoded_signature(None, &sig).unwrap();
        println!("{string}\n{}", crate::qr::data_to_qr(&string).unwrap());
    }
}
