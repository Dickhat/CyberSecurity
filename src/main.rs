pub mod algo;
use crate::algo::RsaData;

fn main() {
    let rsa = RsaData::rsa_512();

    print!("{:?}", rsa);
}
