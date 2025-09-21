pub mod algorithms;
use algorithms::{streebog, hex_to_bytes};


fn main() {
    let mut str1: [u8; 64] = [0; 64];
    let mut str2: [u8; 64] = [0; 64];

    str1[0] = 0x05;
    str2[0] = 0x01;

    let mut message = hex_to_bytes("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130");
    
    // Стрибог 256
    //let mut message = hex_to_bytes("fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1");
    
    message.reverse();

    let hash = streebog::streebog(&message, 256).unwrap();

    // let message = "Hello World!".to_string();
    // // let rsa = RsaData::rsa_512().unwrap();

    // let rsa = RsaData::rsa_512().unwrap();


    // let path_encr = rsa.encryption(&message).unwrap();
    // let path_decr = rsa.decryption(path_encr.clone()).unwrap();

    // println!("Шифрованный файл: {path_encr:?}\nРасшифрованный файл: {path_decr:?}\n");
}
