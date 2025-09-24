pub mod rsa;
pub mod streebog;
pub mod kuznechik;

// Перевод шестнацетиричных чисел в байты (Исходное представление big Endian)
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// функция: байты -> строка из hex-символов (data представлена в little endian)
pub fn to_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);

    for &b in data.iter().rev() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }

    out
}