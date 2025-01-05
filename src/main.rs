use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize_hex,
    key::{Keypair, Secp256k1, TapTweak, TweakedKeypair, UntweakedPublicKey},
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{Signature, TaprootBuilder},
    transaction::Version,
    Address, Amount, CompressedPublicKey, KnownHrp, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
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

    let tx_input = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: Txid::from_str(
                "c9bef7daa7f6ff13698d5bf6a0eca995f009302c241f6aacfef2652c1ab6f856",
            )
            .unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence(0),
        witness: Witness::default(),
    };

    let address_to_send = Address::from_str("bcrt1qd75p224rk59gq20nfupurgq07ga5kjskvfjcpm")
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();

    let send_output = TxOut {
        value: Amount::from_btc(0.05).unwrap(),
        script_pubkey: address_to_send.script_pubkey(),
    };

    let change_output = TxOut {
        value: Amount::from_btc(0.34).unwrap(),
        script_pubkey: taproot_address.script_pubkey(),
    };

    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input],
        output: vec![send_output, change_output],
    };

    let utxo = TxOut {
        value: Amount::from_btc(0.39062500).unwrap(),
        script_pubkey: ScriptBuf::from_hex(
            "5120a433ba91fe28c82c5c8681ef3c0727c246ae533a1b6b6d34a8932c26b78bc6af",
        )
        .unwrap(),
    };
    let prevout = vec![utxo];
    let prevout = Prevouts::All(&prevout);

    let sighash_type = bitcoin::TapSighashType::Default;

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &prevout, sighash_type)
        .unwrap();

    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, tap_tree.merkle_root());
    let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    let signature = Signature {
        signature,
        sighash_type,
    };

    sighasher.witness_mut(0).unwrap().push(&signature.to_vec());
    let tx = sighasher.into_transaction();

    println!("{:#?}", tx);
    println!("raw transaction: {}", serialize_hex(tx));
}
