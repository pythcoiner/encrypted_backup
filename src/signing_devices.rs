use async_hwi::{
    HWI,
    bitbox::{BitBox02, PairingBitbox02WithLocalCache, api::runtime},
    coldcard,
    jade::{self, Jade},
    ledger::{HidApi, Ledger, LedgerSimulator, TransportHID},
    specter::{Specter, SpecterSimulator},
};
use miniscript::{
    DescriptorPublicKey,
    bitcoin::{Network, bip32::DerivationPath},
    descriptor::{DescriptorXKey, Wildcard},
};
use std::{collections::BTreeSet, error::Error};

pub async fn collect_xpubs(deriv_paths: Vec<DerivationPath>) -> Vec<DescriptorPublicKey> {
    let mut devices = vec![];
    let mut xpubs = BTreeSet::new();
    for network in [Network::Bitcoin, Network::Testnet] {
        if let Ok(mut dev) = list(network).await {
            devices.append(&mut dev);
        }
    }
    for device in devices {
        if let Ok(fg) = device.get_master_fingerprint().await {
            for path in &deriv_paths {
                if let Ok(xpub) = device.get_extended_pubkey(path).await {
                    let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
                        origin: Some((fg, path.clone())),
                        xkey: xpub,
                        derivation_path: DerivationPath::default(),
                        wildcard: Wildcard::None,
                    });
                    xpubs.insert(dpk);
                }
            }
        }
    }

    xpubs.into_iter().collect()
}

pub async fn list(network: Network) -> Result<Vec<Box<dyn HWI + Send>>, Box<dyn Error>> {
    let mut hws = Vec::new();

    if let Ok(device) = SpecterSimulator::try_connect().await {
        hws.push(device.into());
    }

    if let Ok(devices) = Specter::enumerate().await {
        for device in devices {
            hws.push(device.into());
        }
    }

    match Jade::enumerate().await {
        Err(e) => println!("{:?}", e),
        Ok(devices) => {
            for device in devices {
                let device = device.with_network(network);
                if let Ok(info) = device.get_info().await {
                    if info.jade_state == jade::api::JadeState::Locked {
                        if let Err(e) = device.auth().await {
                            eprintln!("auth {:?}", e);
                            continue;
                        }
                    }

                    hws.push(device.into());
                }
            }
        }
    }

    if let Ok(device) = LedgerSimulator::try_connect().await {
        hws.push(device.into());
    }

    let api = Box::new(HidApi::new().unwrap());

    for device_info in api.device_list() {
        if async_hwi::bitbox::is_bitbox02(device_info) {
            if let Ok(device) = device_info.open_device(&api) {
                if let Ok(device) =
                    PairingBitbox02WithLocalCache::<runtime::TokioRuntime>::connect(device, None)
                        .await
                {
                    if let Ok((device, _)) = device.wait_confirm().await {
                        let bb02 = BitBox02::from(device).with_network(network);
                        hws.push(bb02.into());
                    }
                }
            }
        }
        if device_info.vendor_id() == coldcard::api::COINKITE_VID
            && device_info.product_id() == coldcard::api::CKCC_PID
        {
            if let Some(sn) = device_info.serial_number() {
                if let Ok((cc, _)) = coldcard::api::Coldcard::open(&api, sn, None) {
                    let hw = coldcard::Coldcard::from(cc);
                    hws.push(hw.into())
                }
            }
        }
    }

    for detected in Ledger::<TransportHID>::enumerate(&api) {
        if let Ok(device) = Ledger::<TransportHID>::connect(&api, detected) {
            hws.push(device.into());
        }
    }

    Ok(hws)
}
