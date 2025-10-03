pub mod rsa;
pub mod streebog;
pub mod kuznechik;
pub mod block_cipher_modes;

/// Печатает символы из байтовой строки с конца. Используется функция для
/// провеки значений при отладке и тестах.
pub fn print_bytes(bytes: &[u8]) {
    for b in bytes[..].iter().rev() {
        print!("{:02x}", b);
    }
}

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

// Суммирование в кольце Z_2^N
pub fn sum_mod2_wo<const N: usize>(left: &[u8; N], right: &[u8; N]) -> [u8; N]
{
    let mut carry: u16 = 0;
    let mut out: [u8; N] = [0; N];

    for idx in 0..N
    {
        let res: u16 = (left[idx] as u16) + (right[idx] as u16) + carry;
        out[idx] = res as u8;       // Обрезает старшие биты
        carry = res >> 8;           // Оставляет старшие биты (бит переноса)
    }

    out
}

// Суммирование по модулю 2
pub fn sum_mod2<const N: usize>(str1: &[u8; N], str2: &[u8; N]) -> [u8; N]
{
    let mut res: [u8; N] = [0; N];

    // Суммирование по модулю 2
    for index in 0..N
    {
        res[index] = str1[index] ^ str2[index];
    }

    res
}