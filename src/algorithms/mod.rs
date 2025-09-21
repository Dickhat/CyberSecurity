pub mod rsa;
pub mod streebog;
pub mod kuznechik;

// Перевод шестнацетиричных чисел в байты
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}