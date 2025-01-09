use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    consensus::encode::serialize_hex,
    key::{Keypair, Secp256k1, TapTweak, TweakedKeypair, UntweakedPublicKey},
    opcodes::all::OP_CHECKSIG,
    script::Builder,
    secp256k1::Message,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, Signature, TaprootBuilder},
    transaction::Version,
    Address, Amount, KnownHrp, ScriptBuf, Sequence, TapLeafHash, Transaction, TxIn, TxOut, Txid,
    Witness,
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

    // pushing x-only-pubkey because OP_CHECKSIG in tapscript uses 32-byte public keys.
    let script1 = Builder::new()
        .push_x_only_key(&key1.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let script2 = Builder::new()
        .push_x_only_key(&key2.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    let script3 = Builder::new()
        .push_x_only_key(&key3.x_only_public_key().0)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let builder = TaprootBuilder::new();
    let builder = builder.add_leaf(1, script1.clone()).unwrap();
    let builder = builder.add_leaf(2, script2.clone()).unwrap();
    let builder = builder.add_leaf(2, script3.clone()).unwrap();

    let tap_tree = builder.finalize(&secp, internal_key.0).unwrap();

    let taproot_address = Address::p2tr(
        &secp,
        internal_key.0,
        tap_tree.merkle_root(),
        KnownHrp::Regtest,
    );

    println!("taproot address: {}", taproot_address);

    let address_to_send = Address::from_str("bcrt1qd75p224rk59gq20nfupurgq07ga5kjskvfjcpm")
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();

    let sighash_type = bitcoin::TapSighashType::Default;

    /* KEY PATH SPEND */
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

    /* KEY PATH SPEND */

    /* SCRIPT PATH SPEND */
    let tx_input = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: Txid::from_str(
                "878e7be2a1be507a86887973ff90f00ba3eaa6fadfafebf407d9d9d89e35ae5f",
            )
            .unwrap(),
            vout: 0,
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence(0),
        witness: Witness::default(),
    };

    let send_output = TxOut {
        value: Amount::from_btc(0.035).unwrap(),
        script_pubkey: address_to_send.script_pubkey(),
    };

    let change_output = TxOut {
        value: Amount::from_btc(0.01).unwrap(),
        script_pubkey: taproot_address.script_pubkey(),
    };

    let mut unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input],
        output: vec![send_output, change_output],
    };

    let utxo = TxOut {
        value: Amount::from_btc(0.04882812).unwrap(),
        script_pubkey: ScriptBuf::from_hex(
            "51204dc0f1988094929d5212ad9062232d937bfc1effd6c2b90cd49c34af0a066e7c",
        )
        .unwrap(),
    };
    let prevouts = vec![utxo];
    let prevouts = Prevouts::All(&prevouts);

    let leaf_hash = TapLeafHash::from_script(
        script1.as_script(),
        bitcoin::taproot::LeafVersion::TapScript,
    );

    let mut sighasher = SighashCache::new(&mut unsigned_tx);
    let sighash = sighasher
        .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, sighash_type)
        .unwrap();

    let msg = Message::from_digest_slice(sighash.as_ref()).unwrap();
    let signature = secp.sign_schnorr(&msg, &key1);

    let signature = Signature {
        signature,
        sighash_type,
    };

    let control_block = tap_tree
        .control_block(&(script1.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(script1.as_bytes());
    witness.push(control_block);

    *sighasher.witness_mut(0).unwrap() = witness;
    let tx = sighasher.into_transaction();

    println!("{:#?}", tx);
    println!("script path spend raw transaction: {}", serialize_hex(tx));

    /* SCRIPT PATH SPEND */
}
