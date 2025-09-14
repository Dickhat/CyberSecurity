pub mod algorithms;
use algorithms::{streebog::consts::A, streebog, hex_to_bytes};


fn main() {
    let mut str1: [u8; 64] = [0; 64];
    let mut str2: [u8; 64] = [0; 64];

    str1[0] = 0x05;
    str2[0] = 0x01;

    let mut message = hex_to_bytes("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130");

    //message.reverse();
    
    streebog::streebog_512(&message);

    print!("[");
    for elem in A.iter().rev()
    {
        print!("{:#018x},", elem);
    }
    print!("]");
    // let message = "Hello World!".to_string();
    // // let rsa = RsaData::rsa_512().unwrap();

    // let rsa = RsaData::rsa_512().unwrap();


    // let path_encr = rsa.encryption(&message).unwrap();
    // let path_decr = rsa.decryption(path_encr.clone()).unwrap();

    // println!("Шифрованный файл: {path_encr:?}\nРасшифрованный файл: {path_decr:?}\n");
}
