use std::path::PathBuf;

use crate::algorithms::hex_to_bytes;

pub mod algorithms;

fn main() {
    //let path = PathBuf::from("./kuznehcik_keys");

    // algorithms::kuznechik::key_generate();
    // let (primary, rounds) = algorithms::kuznechik::get_keys_from_file(&path);

    // let mut message = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
    // message.reverse();

    // algorithms::kuznechik::encryption(&message, &(primary, rounds));
    

    println!();
    // let message = "Hello World!".to_string();
    // // let rsa = RsaData::rsa_512().unwrap();

    // let rsa = RsaData::rsa_512().unwrap();


    // let path_encr = rsa.encryption(&message).unwrap();
    // let path_decr = rsa.decryption(path_encr.clone()).unwrap();

    // println!("Шифрованный файл: {path_encr:?}\nРасшифрованный файл: {path_decr:?}\n");
}
