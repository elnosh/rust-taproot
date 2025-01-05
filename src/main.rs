use bitcoin::{
    hex::DisplayHex,
    key::{Keypair, Secp256k1, UntweakedPublicKey},
    taproot::TaprootBuilder,
    Address, CompressedPublicKey, KnownHrp,
};

fn main() {
    // key for key path spend
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_str(
        &secp,
        "ad4e80f7c21e0dca9375adb974e0169448d08f78e57caa4e02f2ecff27852a4b",
    )
    .unwrap();
    let internal_key = UntweakedPublicKey::from_keypair(&keypair);

    println!("private key: {:x}", keypair.secret_bytes().as_hex());

    // x-only pubkey one of args to p2tr address
    // next need merkle root of taptree
    // create 3 more keys and their respective scripts
    let key1 = Keypair::from_seckey_str(
        &secp,
        "0d1035c36ed609a2e24814649ced6c87a306f5fc4fda386b63fe780ca7cd29e3",
    )
    .unwrap();
    let key2 = Keypair::from_seckey_str(
        &secp,
        "45a4c29dbee8db2458d3078fdad5d97956218435df15a62ae4951f8ef02d56de",
    )
    .unwrap();
    let key3 = Keypair::from_seckey_str(
        &secp,
        "1cb755a11caa1ad4171ffc8d215e372e71db0d167aa184fc713b357fed04871d",
    )
    .unwrap();

    println!("key1: {:x}", key1.secret_bytes().as_hex());
    println!("key2: {:x}", key2.secret_bytes().as_hex());
    println!("key3: {:x}", key3.secret_bytes().as_hex());

    let script1 = CompressedPublicKey::from_slice(&key1.public_key().serialize())
        .unwrap()
        .p2wpkh_script_code();
    let script2 = CompressedPublicKey::from_slice(&key2.public_key().serialize())
        .unwrap()
        .p2wpkh_script_code();
    let script3 = CompressedPublicKey::from_slice(&key3.public_key().serialize())
        .unwrap()
        .p2wpkh_script_code();

    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(1, script1).unwrap();
    let builder = builder.add_leaf(2, script2).unwrap();
    let builder = builder.add_leaf(2, script3).unwrap();

    let tap_tree = builder.finalize(&secp, internal_key.0).unwrap();

    let taproot_address = Address::p2tr(
        &secp,
        internal_key.0,
        tap_tree.merkle_root(),
        KnownHrp::Regtest,
    );

    println!("taproot address: {}", taproot_address);
}
