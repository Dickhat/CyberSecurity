use crate::algorithms::sum_mod2;

use super::{kuznechik::Kuznechik, sum_mod2_wo};

pub struct CipherModes
{
    keys: Kuznechik,
}

impl CipherModes {
    /// Создание структуры CipherModes с хранилищем ключей внутри,
    /// также обеспечивает вызов методов шифрования/расшифрования блочных шифров
    pub fn new() -> Self
    {
        Self { keys: Kuznechik::new()}
    }

    // ГОСТ Р 34.13-2018 paragraph 4.1.3
    fn padding_proc2(message: &[u8]) -> [u8; 16]
    {
        let mut padded_message: [u8; 16] = [0; 16];

        padded_message[16 - message.len()..].copy_from_slice(message); // P || 0..0
        padded_message[16 - message.len() - 1] = 0b1000_0000;               // P || 10..0

        padded_message
    }

    /// Режим простой замены (Electronic Codebook). При длине сообщения < 128
    /// до шифрования осуществляет padding по схеме ГОСТ Р 34.13-2018 paragraph 4.1.3
    pub fn ecb_encrypt(&self, message: &[u8]) -> Vec<[u8; 16]>
    {
        let mut encrypted_message: Vec<[u8; 16]> = vec![];
        let mut padded_chunk: [u8; 16];

        // Шифрование блоками по 128 бит
        for chunk in message.chunks(16)
        {
            // 16 байт = 128 бит
            if chunk.len() != 16
            {
                padded_chunk = Self::padding_proc2(chunk);

                // Проверка, что вернулось
                match self.keys.encrypt(&padded_chunk[..]) {
                    Ok(data) => {encrypted_message.push(data);},
                    Err(err_msg) => {panic!("{err_msg}");}
                }
            }
            else {
                // Проверка, что вернулось
                match self.keys.encrypt(chunk) {
                    Ok(data) => {encrypted_message.push(data);},
                    Err(err_msg) => {panic!("{err_msg}");}
                }
            }
        }

        encrypted_message
    }

    /// Режим простой замены (Electronic Codebook). Расшифровывает шифротекст
    /// а также убирает padding по схеме ГОСТ Р 34.13-2018 paragraph 4.1.3
    pub fn ecb_decrypt(&self, message: &[u8]) -> Vec<u8>
    {
        let mut encrypted_message: Vec<u8> = vec![];

        // Шифрование блоками по 128 бит
        for chunk in message.chunks(16)
        {
            // 16 байт = 128 бит
            // Проверка, что вернулось
            match self.keys.decrypt(chunk) {
                Ok(data) => {encrypted_message.extend_from_slice(&data);},
                Err(err_msg) => {panic!("{err_msg}");}
            }
        }

        // Убрать padding (padding_proc2) в последних 16 байтах
        let idx_check_byte = encrypted_message.len() - 16;
        while encrypted_message[idx_check_byte] == 0 || encrypted_message[idx_check_byte] == 128
        {
            encrypted_message.remove(idx_check_byte);
        }

        encrypted_message
    }

    // 5.2.1 (3)
    fn add_ctr(ctr: &[u8; 16]) -> [u8; 16]
    {
        let mut one: [u8; 16] = [0; 16];
        one[0] = 1;

        sum_mod2_wo(ctr, &one)
    }

    // Взятие s старших бит из str_a
    fn msb(str_a: &[u8], s: usize) -> Vec<u8>
    {
        let mut res = str_a.to_vec();
        let mask: u8 = !((1 << s % 8) - 1);     // Обратная маска для зануления младших бит
        res[s/8] &= mask;                       // Зануление младших бит

        res
    }

    /// Режим гаммирования (Counter) с входным сообщением message, представленным срезом байтов
    /// Параметром s, представляющем число бит шифрования, и IV - инициализирующим вектором,
    /// который для каждого нового сообщения формируется новый
    pub fn ctr_encrypt(&self, message: &[u8], s: usize, iv: &[u8; 8]) -> Vec<u8>
    {
        // s - число бит, которые будут шифроваться
        if s > 128
        {
            panic!("S must be <= 128");
        }

        let mut res:Vec<u8> = vec![];

        // CTR1 = IV||0..0
        let mut ctr: [u8; 16] = [0; 16];
        ctr[8..].copy_from_slice(iv);

        // Данные для анализа байтов
        let chunk_size = if s%8 == 0 {s/8} else {s/8 + 1};
        let bits_check = s%8;

        let cur_idx = 0;

        // Доделать битовое шифрование
        while cur_idx <= message.len()
        {
            // 5.2.2 (4)
            let ek_ctr = self.keys.encrypt(&ctr).unwrap();

            // Обрезание младших бит у ctr
            let gamma = Self::msb(&ek_ctr, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обрезание младших бит у part
            let trunc_part = Self::msb(&message[cur_idx..(cur_idx + chunk_size)], s);
            let part_u8:&[u8; 16] = trunc_part[..].try_into().unwrap();
        }

        // Побайтовая итерация, при которой анализируются биты
        for part in message.chunks(chunk_size)
        {
            // 5.2.2 (4)
            let ek_ctr = self.keys.encrypt(&ctr).unwrap();

            // Обрезание младших бит у ctr
            let gamma = Self::msb(&ek_ctr, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обрезание младших бит у part
            let trunc_part = Self::msb(part, s);
            let part_u8:&[u8; 16] = trunc_part[..].try_into().unwrap();

            let c = sum_mod2(part_u8, gamma_u8);

            if !res.is_empty()
            {
                let last = res.last_mut().unwrap();
                *last |= c[0];
            }

            res.extend(c);      // Помещение результата в массив

            ctr = Self::add_ctr(&ctr);
        }

        res
    }

    pub fn ctr_decrypt()
    {

    }
}

#[cfg(test)]
mod tests
{
    use crate::algorithms::{hex_to_bytes, to_hex};
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_ecb_encrypt_decrypt()
    {
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        let mut message: Vec<u8> = [p1.clone(), p2.clone(), p3.clone(), p4.clone()].into_iter().flatten().collect();

        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        let mut result = kuz_ecb.ecb_encrypt(&message[..]);

        // Little-endian по ГОСТ-у перевести в обычное отображение
        result[0].reverse();
        result[1].reverse();
        result[2].reverse();
        result[3].reverse();

        // Правильный результат шифротекста
        let c1 = hex_to_bytes("7f679d90bebc24305a468d42b9d4edcd");
        let c2 = hex_to_bytes("b429912c6e0032f9285452d76718d08b");
        let c3 = hex_to_bytes("f0ca33549d247ceef3f5a5313bd4b157");
        let c4 = hex_to_bytes("d0b09ccde830b9eb3a02c4c5aa8ada98");

        assert_eq!(result[0].to_vec(), c1);
        assert_eq!(result[1].to_vec(), c2);
        assert_eq!(result[2].to_vec(), c3);
        assert_eq!(result[3].to_vec(), c4);

        // Перевод в little-endian
        result[0].reverse();
        result[1].reverse();
        result[2].reverse();
        result[3].reverse();

        message = [result[0], result[1], result[2], result[3]].into_iter().flatten().collect();

        let decrypt_result = kuz_ecb.ecb_decrypt(&message[..]);

        assert_eq!(decrypt_result[0..16], p1);
        assert_eq!(decrypt_result[16..32], p2);
        assert_eq!(decrypt_result[32..48], p3);
        assert_eq!(decrypt_result[48..], p4);
    }

    #[test]
    fn test_ecb_encrypt_decrypt_with_padding()
    {
        let message = "Hello world!!! That's message generate automatically. Or not. POOP!".as_bytes();

        let kuz_ecb = CipherModes::new();

        let encrypted_result = kuz_ecb.ecb_encrypt(message);
        let decrypted_result = kuz_ecb.ecb_decrypt(&encrypted_result.into_iter().flatten().collect::<Vec<u8>>()[..]);

        //println!("Decrypted result = {}", String::from_utf8(decrypted_result.clone()).unwrap());

        assert_eq!(decrypted_result, message);
    }


}
