// src/main.rs

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use base58::ToBase58;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
type HmacSha512 = Hmac<sha2::Sha512>;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

mod wordlist;
use wordlist::get_wordlist;

fn main() {
    loop {
        println!();
        println!("=== BIP39 TOOL (Partie A TD2) ===");
        println!("1) Générer une nouvelle seed + mnemonic");
        println!("2) Importer une phrase mnémonique");
        println!("3) Quitter");
        print!("Choix: ");
        flush_stdout();

        let choice = read_line_trim();
        match choice.as_str() {
            "1" => generate_flow(),
            "2" => import_flow(),
            "3" => {
                println!("Bye !");
                break;
            }
            _ => println!("Choix invalide."),
        }
    }
}

fn generate_flow() {
    let wordlist = get_wordlist();

    println!("\nTaille de l'entropie (en bits) ? [128 ou 256 recommandé]");
    print!("ENT = ");
    flush_stdout();
    let ent_str = read_line_trim();
    let ent: usize = ent_str.parse().unwrap_or(128);

    if ![128, 160, 192, 224, 256].contains(&ent) {
        println!("ENT doit être parmi [128,160,192,224,256]. On prend 128.");
        return;
    }

    // ----------- ENTROPY -----------
    let entropy_bytes_len = ent / 8;
    let mut entropy = vec![0u8; entropy_bytes_len];
    OsRng.fill_bytes(&mut entropy);

    println!("\n=== ENTROPY ===");
    println!("Bytes   : {:?}", entropy);
    println!("Hex     : {}", hex::encode(&entropy));
    println!("Binaire : {}", bytes_to_binary_string(&entropy));

    // ---------- CHECKSUM ----------
    let cs_len = ent / 32;
    let checksum_bits = calc_checksum_bits(&entropy, cs_len);

    // ---------- ENT + CS ----------
    let mut bits = bytes_to_bits(&entropy);
    bits.extend_from_slice(&checksum_bits);

    let num_words = bits.len() / 11;
    let mut words = Vec::new();

    println!("\n=== Groupes de 11 bits ===");
    for i in 0..num_words {
        let chunk = &bits[i * 11..(i + 1) * 11];
        let index = bits_to_u16(chunk);
        let word = wordlist[index as usize];

        let chunk_str: String = chunk.iter().map(|b| char::from(b'0' + *b)).collect();
        println!("{} -> {:4} -> {}", chunk_str, index, word);

        words.push(word);
    }

    let mnemonic = words.join(" ");
    println!("\n=== MNEMONIC ===");
    println!("{mnemonic}");

    // ---------- BIP39 SEED ----------
    let salt = b"mnemonic";
    let mut seed = [0u8; 64];

    pbkdf2_hmac::<sha2::Sha512>(mnemonic.as_bytes(), salt, 2048, &mut seed);

    println!("\n=== BIP39 SEED ===");
    println!("Seed (hex) : {}", hex::encode(&seed));

    // ---------- BIP32 ROOT KEY (xprv) ----------

    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
    mac.update(&seed);
    let result = mac.finalize().into_bytes();

    let master_priv = &result[..32];
    let master_chaincode = &result[32..];

    // Construction des champs BIP32
    let version: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
    let depth: u8 = 0;
    let parent_fingerprint: [u8; 4] = [0, 0, 0, 0];
    let child_number: [u8; 4] = [0, 0, 0, 0];

    // La clé privée BIP32 commence toujours par 0x00
    let mut key_data = vec![0x00];
    key_data.extend_from_slice(master_priv);

    // Assemble en un seul buffer
    let mut raw = Vec::new();
    raw.extend_from_slice(&version);
    raw.push(depth);
    raw.extend_from_slice(&parent_fingerprint);
    raw.extend_from_slice(&child_number);
    raw.extend_from_slice(master_chaincode);
    raw.extend_from_slice(&key_data);

    // Checksum (double SHA256)
    let checksum = sha2::Sha256::digest(&sha2::Sha256::digest(&raw));
    let checksum4 = &checksum[..4];

    // xprv final = base58(raw + checksum)
    let mut extended = raw.clone();
    extended.extend_from_slice(checksum4);
    let xprv = extended.to_base58();

    println!("\n=== BIP32 ROOT KEY ===");
    println!("xprv : {}", xprv);

        // ========= BIP32 (TD2) =========

    // 1) Master public key
    let master_pub = bip32_master_pubkey(master_priv);
    println!("\n=== BIP32 MASTER PUBLIC KEY ===");
    println!("Master pubkey (compressed) : {}", hex::encode(master_pub));

    // 2) Child key à un index fixe (ex: 0)
    let secp = Secp256k1::new();
    let master_sk = SecretKey::from_slice(master_priv).expect("master priv");
    let (child0_sk, child0_cc) = bip32_ckd_priv(&master_sk, master_chaincode, 0);
    println!("\n=== CHILD KEY (index 0) ===");
    println!("Child[0] priv : {}", hex::encode(&child0_sk[..]));
    println!("Child[0] chain code : {}", hex::encode(&child0_cc));

    // 3) Child key à un index N demandé à l'utilisateur
    println!("\nIndex N pour une child key (non-hardened) ?");
    print!("N = ");
    flush_stdout();
    let n_str = read_line_trim();
    let n: u32 = n_str.parse().unwrap_or(1);

    let (childN_sk, childN_cc) = bip32_ckd_priv(&master_sk, master_chaincode, n);
    println!("\n=== CHILD KEY (index {n}) ===");
    println!("Child[{n}] priv : {}", hex::encode(&childN_sk[..]));
    println!("Child[{n}] chain code : {}", hex::encode(&childN_cc));

    // 4) Child key à un chemin de profondeur M (ex: m / i0 / i1 / ...)

    println!("\nNombre de niveaux M pour la dérivation (ex: 2 pour m/i0/i1) ?");
    print!("M = ");
    flush_stdout();
    let m_str = read_line_trim();
    let m: usize = m_str.parse().unwrap_or(2);

    let mut path: Vec<u32> = Vec::new();
    for level in 0..m {
        println!("Index pour le niveau {} (i{} dans m/.../i{}) ?", level + 1, level, level);
        print!("i{} = ", level);
        flush_stdout();
        let idx_str = read_line_trim();
        let idx: u32 = idx_str.parse().unwrap_or(0);
        path.push(idx);
    }

    let (path_sk, path_cc) = bip32_derive_path(master_priv, master_chaincode, &path);
    println!("\n=== CHILD KEY au bout du chemin m/{:?} ===", path);
    println!("Priv key : {}", hex::encode(&path_sk[..]));
    println!("Chain code : {}", hex::encode(&path_cc));


}

fn import_flow() {
    let wordlist = get_wordlist();

    println!("\nEntre ta phrase mnémonique BIP39 (anglais):");
    let mnemonic = read_line_trim();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        println!("Nombre de mots invalide !");
        return;
    }

    let mut all_bits = Vec::new();

    for w in &words {
        match wordlist.iter().position(|&x| x == *w) {
            Some(idx) => {
                let mut chunk = u11_to_bits(idx as u16);
                all_bits.append(&mut chunk);
            }
            None => {
                println!("Mot inconnu : {w}");
                return;
            }
        }
    }

    let total_bits = all_bits.len();
    let ent_bits = total_bits * 32 / 33;
    let cs_bits = total_bits - ent_bits;

    let entropy_bits = &all_bits[..ent_bits];
    let checksum_bits = &all_bits[ent_bits..];

    let entropy = bits_to_bytes(entropy_bits);

    println!("\n=== ENTROPY RECONSTRUITE ===");
    println!("Hex : {}", hex::encode(&entropy));

    let expected_cs = calc_checksum_bits(&entropy, cs_bits);

    println!("Checksum attendu : {}", bits_to_string(&expected_cs));
    println!("Checksum donné   : {}", bits_to_string(checksum_bits));

    if expected_cs == checksum_bits {
        println!("Mnemonic VALIDÉ !");
    } else {
        println!("Mnemonic INCORRECT !");
    }
}

/* =========== HELPERS =========== */

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::new();
    for b in bytes {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut cur = 0u8;

    for (i, bit) in bits.iter().enumerate() {
        cur = (cur << 1) | (bit & 1);
        if i % 8 == 7 {
            bytes.push(cur);
            cur = 0;
        }
    }
    bytes
}

fn calc_checksum_bits(entropy: &[u8], cs_len: usize) -> Vec<u8> {
    let hash = Sha256::digest(entropy);
    let mut bits = bytes_to_bits(&hash);
    bits.truncate(cs_len);
    bits
}

fn bits_to_u16(bits: &[u8]) -> u16 {
    bits.iter().fold(0, |acc, &b| (acc << 1) | b as u16)
}

fn u11_to_bits(v: u16) -> Vec<u8> {
    (0..11).rev().map(|i| ((v >> i) & 1) as u8).collect()
}

fn bytes_to_binary_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:08b}", b)).collect::<Vec<_>>().join(" ")
}

fn bits_to_string(bits: &[u8]) -> String {
    bits.iter().map(|b| char::from(b'0' + *b)).collect()
}

fn read_line_trim() -> String {
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().into()
}

fn flush_stdout() {
    io::stdout().flush().unwrap();
}

/* ========= BIP32 HELPERS ========= */

// renvoie la clé publique compressée (33 bytes) à partir d'une clé privée 32 bytes
fn bip32_master_pubkey(master_priv: &[u8]) -> [u8; 33] {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(master_priv).expect("master priv key invalide");
    let pk = PublicKey::from_secret_key(&secp, &sk);
    pk.serialize()
}

// CKDpriv : dérivation d'une child key (non hardened) à partir d'une clé privée + chain code + index
fn bip32_ckd_priv(
    parent_sk: &SecretKey,
    parent_chaincode: &[u8],
    index: u32,
) -> (SecretKey, [u8; 32]) {
    let secp = Secp256k1::new();

    // data = serP(K_par) || ser32(i)
    let parent_pk = PublicKey::from_secret_key(&secp, parent_sk);
    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(&parent_pk.serialize());
    data.extend_from_slice(&index.to_be_bytes());

    // I = HMAC-SHA512(chaincode, data)
    let mut mac = HmacSha512::new_from_slice(parent_chaincode).unwrap();
    mac.update(&data);
    let i = mac.finalize().into_bytes();
    let (il, ir) = i.split_at(32);

    // child_sk = il + k_par (mod n)
    let secp = Secp256k1::new();

    // il = left 32 bytes from HMAC
    let mut il32 = [0u8; 32];
    il32.copy_from_slice(&il);

    // 1) (IL mod n) doit devenir un Scalar
    use secp256k1::Scalar;

    let tweak = Scalar::from_be_bytes(il32)
        .expect("IL invalide pour Scalar");

    // 2) child_sk = parent_sk + IL  (mod n)
    let mut child_sk = parent_sk.clone();
    child_sk.add_tweak(&tweak)
        .expect("Erreur: add_tweak hors domaine");



    let mut child_chaincode = [0u8; 32];
    child_chaincode.copy_from_slice(ir);

    (child_sk, child_chaincode)
}

// dérive une clé à un chemin de type m / i0 / i1 / ... (non hardened)
fn bip32_derive_path(
    master_priv: &[u8],
    master_chaincode: &[u8],
    path: &[u32],
) -> (SecretKey, [u8; 32]) {
    let secp = Secp256k1::new();

    let mut sk = SecretKey::from_slice(master_priv).expect("master priv");
    let mut cc = {
        let mut tmp = [0u8; 32];
        tmp.copy_from_slice(master_chaincode);
        tmp
    };

    for index in path {
        let (child_sk, child_cc) = bip32_ckd_priv(&sk, &cc, *index);
        sk = child_sk;
        cc = child_cc;
    }

    (sk, cc)
}
