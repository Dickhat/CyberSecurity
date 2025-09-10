pub mod algo;
use crate::algo::RsaData;

fn main() {
    let message = "Hello World!".to_string();
    let rsa = RsaData::rsa_512().unwrap();

    let path_encr = rsa.encryption(&message).unwrap();
    let path_decr = rsa.decryption(path_encr.clone()).unwrap();

    println!("Шифрованный файл: {path_encr:?}\nРасшифрованный файл: {path_decr:?}\n");
}
