use std::vec;

use super::{kuznechik::Kuznechik, sum_mod2, sum_mod2_wo, sum_mod2_slice};

pub struct CMAC
{
    k: Vec<u8>,
    k1: [u8; 16],
    k2: [u8; 16],
}

pub struct CipherModes
{
    keys: Kuznechik
}

impl CMAC {
    /// Генерация вспомогательных ключей K, K1, K2 для CMAC
    pub fn new() -> Result<Self, String>
    {
        let keys = Kuznechik::new();
        let zeroes: [u8; 16] = [0; 16];

        // В_128= 0^128 | 10000111
        let mut b: [u8; 16] = [0; 16];
        b[0] = 0b1000_0111;
        
        let r = keys.encrypt(&zeroes)?;
        let mut k1:[u8; 16] = [0; 16];
        let mut k2:[u8; 16] = [0; 16];

        // R << 1
        for idx in 0..16
        {
            if idx == 15
            {
                k1[0] = r[0] << 1;
            }
            else {
                k1[15 - idx] = (r[15 - idx] << 1) | (r[15 - idx - 1] >> 7);
            }
        }

        // MSB_1(R) != 0
        if (r[15] & 0b1000_0000) != 0
        {
            k1 = sum_mod2(&k1, &b);
        }

        // K1 << 1
        for idx in 0..16
        {
            if idx == 15
            {
                k2[0] = k1[0] << 1;
            }
            else {
                k2[15 - idx] = (k1[15 - idx] << 1) | (k1[15 - idx - 1] >> 7);
            }
        }

        // MSB_1(K1) != 0
        if (k1[15] & 0b1000_0000) != 0
        {
            k2 = sum_mod2(&k2, &b);
        }

        Ok(Self {k: keys.keys.0, k1, k2})
    }

    /// Процедура вычисления значения имитовставки (Message Authentication Code algorithm),
    /// где s - число бит имитовставки, а message является сообщением, для которого рассчитывается имитовставка.
    pub fn cmac(&self, message: &[u8], s: usize) -> Result<Vec<u8>, String>
    {
        // s - число бит, которые будут шифроваться
        if s < 1 || s > 128
        {
            panic!("S must be <= 128");
        }

        let mut mac:[u8; 16] = [0; 16];
        let mut c:[u8; 16] = [0; 16];
        let mut chunk_u8:[u8; 16];

        let kuz_keys: Kuznechik = Kuznechik{keys: Kuznechik::key_generate_with_precopmuted_key(&self.k)}; // Вспомогательные ключи Кузнечика

        // Взятие по 128 бит
        for (cur_chunk, chunk) in message.chunks(16).enumerate()
        {
            chunk_u8 = [0; 16];
            // Перевод в срез фиксированного размера
            chunk_u8[0..chunk.len()].copy_from_slice(chunk);

            // Если последние биты message
            if chunk.len() != 16 || ((cur_chunk + 1) * 16 >= message.len())
            {   
                // Дополнение
                if chunk.len() < 16
                {
                    chunk_u8 = CipherModes::padding_proc2(chunk);
                }

                // P_q + C_(q-1)
                chunk_u8 = sum_mod2(&chunk_u8, &c);

                // Длина последнего блока 128 бит
                if chunk.len() == 16 {
                    chunk_u8 = sum_mod2(&chunk_u8, &self.k1);
                }
                else {
                    chunk_u8 = sum_mod2(&chunk_u8, &self.k2);
                }  

                mac = Kuznechik::encrypt(&kuz_keys, &chunk_u8)?;
            } else {
                // C_i = e_k(P_i + C_(i-1))
                c = Kuznechik::encrypt(&kuz_keys, &sum_mod2(&chunk_u8, &c))?;
            }
        }
        
        // Удаление из массива зануленной (обрезанной) части
        let mut vec_mac = CipherModes::msb(&mac[..], s);
        for _ in 0..(s/8) {vec_mac.remove(0);}
        
        Ok(vec_mac)
    }
}

impl CipherModes {
    /// Создание структуры CipherModes с хранилищем ключей внутри,
    /// также обеспечивает вызов методов шифрования/расшифрования блочных шифров
    pub fn new() -> Self
    {
        Self { keys: Kuznechik::new()}
    }

    /// Производит дополнение по алгоритму ГОСТ Р 34.13-2018 paragraph 4.1.3
    fn padding_proc2(message: &[u8]) -> [u8; 16]
    {
        let mut padded_message: [u8; 16] = [0; 16];

        padded_message[16 - message.len()..].copy_from_slice(message); // P || 0..0
        padded_message[16 - message.len() - 1] = 0b1000_0000;               // P || 10..0

        padded_message
    }

    // 5.2.1 (3)
    fn add_ctr(ctr: &[u8; 16]) -> [u8; 16]
    {
        let mut one: [u8; 16] = [0; 16];
        one[0] = 1;

        sum_mod2_wo(ctr, &one)
    }

    // Взятие s старших бит из str_a
    pub fn msb(str_a: &[u8], s: usize) -> Vec<u8>
    {
        let mut res = str_a.to_vec();
        let len_res = res.len()*8;

        // Сколько бит и байт занулить
        let byte_count = (len_res - s)/8;
        let bit_count = (len_res - s)%8;

        if bit_count != 0 {
            // Маска для оставления только старших bit_idx бит
            let mask: u8 = 0xFF << bit_count;
            res[byte_count] &= mask;
        }

        // Обнуляем все байты после нужного
        for i in 0..byte_count {
            res[i] = 0;
        }

        res
    }

    // Взятие s младших бит из str_a
    // fn lsb(str_a: &[u8], s: usize) -> Vec<u8>
    // {
    //     let mut res = str_a.to_vec();

    //     if res.len() == s/8 {return res;}

    //     // С какого бита и байта занулять
    //     let byte_count = s/8;
    //     let bit_count = s%8;

    //     // Маска для оставления только младших bit_count бит
    //     let mask: u8 = if bit_count == 0 {0x00} else {0xFF >> (8 - bit_count)};
    //     res[byte_count] &= mask;

    //     // Обнуляем все байты после нужного
    //     for i in (byte_count + 1)..res.len() {
    //         res[i] = 0;
    //     }

    //     res
    // }


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

    /// Режим простой замены (Electronic Codebook). Расшифровывает шифротекст,
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

    /// Режим гаммирования (Counter) с входным сообщением message, представленным срезом байтов,
    /// параметром s в диапазоне [1; 128], представляющем число бит шифрования, и IV - инициализирующим вектором,
    /// который для каждого нового сообщения должен формироваться новый. С помощью данного метода
    /// можно прозводить как шифрование сообщений, так и расшифрование.
    pub fn ctr_crypt(&self, message: &[u8], s: usize, iv: &[u8; 8]) -> Vec<u8>
    {
        // s - число бит, которые будут шифроваться
        if s < 1 || s > 128
        {
            panic!("S must be <= 128");
        }

        let mut res:Vec<u8> = vec![];

        // CTR1 = IV||0..0
        let mut ctr: [u8; 16] = [0; 16];
        ctr[8..].copy_from_slice(iv);

        let mut c = 0;      // C_i
        let mut cur_idx = 0;     // Текущий обрабатываемый бит
        let mut cur_byte = 0;    // Текущий обрабатываемый байт

        // Шифрование сообщения блоками длины s
        loop
        {
            // Проверка, что все биты обработаны
            if (cur_idx + cur_byte*8) >= message.len()*8 {break;}

            // Сколько осталось отработать бит из s на данный момент
            let mut rem_bits = s;

            let ek_ctr = self.keys.encrypt(&ctr).unwrap();

            // Зануление младших бит у ctr
            let gamma = Self::msb(&ek_ctr, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обработка rem_bit = s
            let mut byte_m:u8;      // Байт message
            let mut byte_ctr:u8;    // Байт Ctr

            // Пока остались биты на обработку
            while rem_bits != 0 
            {
                if cur_byte >= message.len() {break;}

                // Если message[cur_byte] = 0101 1100 и cur_idx = 3
                byte_m = message[cur_byte] >> cur_idx; // Зануление младших обработанных битов даст byte = 0000 1011
                byte_m = byte_m << cur_idx;            // Возврат к исходному положению не зануленных бит byte = 0101 1000
                
                // Часть ctr
                byte_ctr = gamma_u8[cur_byte % 16] >> cur_idx;
                byte_ctr = byte_ctr << cur_idx; 

                // Если операция выполняется на нескольких байтах
                if (cur_idx + rem_bits) > 8
                {
                    rem_bits = rem_bits - (8 - cur_idx);

                    // Переход к следующему байту
                    cur_idx = 0;
                    cur_byte += 1;
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2
                    res.push(c);                  // Помещение результата в массив
                    c = 0;                        // Обнуление результата нового байта
                }
                // Если операция выполняется на одном байте
                else {
                    // Если message[cur_byte] = 0001 1100 и cur_idx = 3 и s = 2 
                    byte_m = byte_m >> cur_idx;                    // Зануление младших обработанных битов byte = 0000 0011
                    byte_m = byte_m << cur_idx;                    // Возврат к исходному положению byte = 0001 1000
                    byte_m = byte_m << (8 - (cur_idx + rem_bits)); // Зануление старших бит, которые обрабатывать не надо, даст byte = 1100 0000
                    byte_m = byte_m >> (8 - (cur_idx + rem_bits)); // Возврат к исходному положению byte = 0001 100

                    // Часть ctr
                    byte_ctr = byte_ctr >> cur_idx;
                    byte_ctr = byte_ctr << cur_idx;
                    byte_ctr = byte_ctr << (8 - (cur_idx + rem_bits));
                    byte_ctr = byte_ctr >> (8 - (cur_idx + rem_bits)); 
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2 (Если s < 8, то добавляем части предыдущего результата)

                    // Сдвиг индекса обрабатываемого бита
                    if (cur_idx + rem_bits) == 8 
                    {
                        // Если полностью обработан текущий байт
                        cur_byte += 1; 
                        cur_idx = 0;

                        res.push(c);
                        c = 0;
                    } 
                    else {
                        cur_idx += rem_bits;
                    };

                    rem_bits -= rem_bits;
                }
            }

            ctr = Self::add_ctr(&ctr);
        }

        res
    }


    /// Режим гаммирования с обратной связью по выходу (Output Feedback) с входным сообщением
    /// message, представленным срезом байтов, параметром s, представляющем число бит шифрования,
    /// параметром m = 128*z, где z - целое >= 1, а также IV - инициализирующим вектором длины m,
    /// который для каждого нового сообщения должен формироваться новый. С помощью данного метода
    /// можно прозводить как шифрование сообщений, так и расшифрование.
    pub fn ofb_crypt(&self, message: &[u8], s: usize, z:usize, iv: & Vec<u8>) -> Vec<u8>
    {
        // s - число бит, которые будут шифроваться
        if s < 1 || s > 128
        {
            panic!("S must be <= 128");
        }

        // z - целое для определения длины регистра и размера IV
        if z < 1
        {
            panic!("Z must be >= 1");
        }

        let m = 128*z/8;            // Длина m в байтах
        let mut r = vec![0u8; m]; // Регистр длины m байт

        r.copy_from_slice(iv);

        let mut res:Vec<u8> = vec![];

        let mut c = 0;              // Байт результата
        let mut cur_idx = 0;     // Текущий обрабатываемый бит
        let mut cur_byte = 0;    // Текущий обрабатываемый байт

        // Шифрование сообщения блоками длины s со сдвигом регистра R
        loop
        {
            // Проверка, что все биты обработаны
            if (cur_idx + cur_byte*8) >= message.len()*8 {break;}

            // Сколько осталось отработать бит из s на данный момент
            let mut rem_bits = s;

            // Передача старшей части регистра R
            let ek_r = self.keys.encrypt(&r[(m - 16)..]).unwrap();

            // Зануление младших бит у ek_r (T_s)
            let gamma = Self::msb(&ek_r, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обработка rem_bit = s
            let mut byte_m:u8;      // Байт message
            let mut byte_ctr:u8;    // Байт Ctr

            // Пока остались биты на обработку
            while rem_bits != 0 
            {
                if cur_byte >= message.len() {break;}

                // Если message[cur_byte] = 0101 1100 и cur_idx = 3
                byte_m = message[cur_byte] >> cur_idx; // Зануление младших обработанных битов даст byte = 0000 1011
                byte_m = byte_m << cur_idx;            // Возврат к исходному положению не зануленных бит byte = 0101 1000
                
                // Часть ctr
                byte_ctr = gamma_u8[cur_byte % 16] >> cur_idx;
                byte_ctr = byte_ctr << cur_idx; 

                // Если операция выполняется на нескольких байтах
                if (cur_idx + rem_bits) > 8
                {
                    rem_bits = rem_bits - (8 - cur_idx);

                    // Переход к следующему байту
                    cur_idx = 0;
                    cur_byte += 1;
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2
                    res.push(c);                  // Помещение результата в массив
                    c = 0;                        // Обнуление результата нового байта
                }
                // Если операция выполняется на одном байте
                else {
                    // Если message[cur_byte] = 0001 1100 и cur_idx = 3 и s = 2 
                    byte_m = byte_m >> cur_idx;                    // Зануление младших обработанных битов byte = 0000 0011
                    byte_m = byte_m << cur_idx;                    // Возврат к исходному положению byte = 0001 1000
                    byte_m = byte_m << (8 - (cur_idx + rem_bits)); // Зануление старших бит, которые обрабатывать не надо, даст byte = 1100 0000
                    byte_m = byte_m >> (8 - (cur_idx + rem_bits)); // Возврат к исходному положению byte = 0001 100

                    // Часть ctr
                    byte_ctr = byte_ctr >> cur_idx;
                    byte_ctr = byte_ctr << cur_idx;
                    byte_ctr = byte_ctr << (8 - (cur_idx + rem_bits));
                    byte_ctr = byte_ctr >> (8 - (cur_idx + rem_bits)); 
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2 (Если s < 8, то добавляем части предыдущего результата)

                    // Сдвиг индекса обрабатываемого бита
                    if (cur_idx + rem_bits) == 8 
                    {
                        // Если полностью обработан текущий байт
                        cur_byte += 1; 
                        cur_idx = 0;

                        res.push(c);
                        c = 0;
                    } 
                    else {
                        cur_idx += rem_bits;
                    };

                    rem_bits -= rem_bits;
                }
            }

            // Младшие биты регистра R
            let lsb_r = r[..(m - 16)].to_vec();

            // R = LSB_[m-n](R) || ek_r
            r[16..].copy_from_slice(&lsb_r);
            r[..16].copy_from_slice(&ek_r);
        }

        res
    }

    /// Режим простой замены с зацеплением (Cipher Block Chaining) с входным сообщением
    /// message, представленным срезом байтов, параметром m = 128*z, где z - целое >= 1,
    /// а также IV - инициализирующим вектором длины m, который для каждого нового сообщения должен формироваться новый.
    /// Данная функция производит шифрование, при чем если message не кратно 128 битам, то происходит
    /// дополнение с помощью padding_proc2.
    pub fn cbc_encrypt(&self, message: &[u8], z:usize, iv: & Vec<u8>) -> Vec<u8>
    {
        // z - целое для определения длины регистра и размера IV
        if z < 1
        {
            panic!("Z must be >= 1");
        }

        let m = 128*z/8;            // Длина m в байтах
        let mut r = vec![0u8; m]; // Регистр длины m байт
        r.copy_from_slice(iv);

        let mut res:Vec<u8> = vec![];
        let mut padded_chunk;

        for chunk in message.chunks(16)
        {
            let c: [u8; 16];

            // Если нужен padding
            if chunk.len() != 16 {
                padded_chunk = Self::padding_proc2(chunk).to_vec();
                c = self.keys.encrypt(&sum_mod2_slice(&padded_chunk[..],&r[(m - 16)..]).unwrap()).unwrap();
            }
            else {
                c = self.keys.encrypt(&sum_mod2_slice(&chunk[..],&r[(m - 16)..]).unwrap()).unwrap();
            }

            res.extend_from_slice(&c);

            // Младшие биты регистра R
            let lsb_r = r[..(m - 16)].to_vec();

            // R = LSB_[m-n](R) || ek_r
            r[16..].copy_from_slice(&lsb_r);
            r[..16].copy_from_slice(&c);
        }

        res
    }

    /// Режим простой замены с зацеплением (Cipher Block Chaining) с входным сообщением
    /// message, представленным срезом байтов, параметром m = 128*z, где z - целое >= 1,
    /// а также IV - инициализирующим вектором длины m, который для каждого нового сообщения должен формироваться новый.
    /// Данная функция производит расшифрование, при чем если message было дополнено, то происходит удаление
    /// дополнения padding_proc2.
    pub fn cbc_decrypt(&self, message: &[u8], z:usize, iv: & Vec<u8>) -> Vec<u8>
    {
        // z - целое для определения длины регистра и размера IV
        if z < 1
        {
            panic!("Z must be >= 1");
        }

        let m = 128*z/8;            // Длина m в байтах
        let mut r = vec![0u8; m]; // Регистр длины m байт
        r.copy_from_slice(iv);

        let mut res:Vec<u8> = vec![];

        for chunk in message.chunks(16)
        {
            // P = D_k(C) sum_mod_2 MSB_n(R)
            let p = sum_mod2_slice(&self.keys.decrypt(chunk).unwrap(), &r[(m - 16)..]).unwrap();

            // Младшие биты регистра R
            let lsb_r = r[..(m - 16)].to_vec();

            // R = LSB_[m-n](R) || ek_r
            r[16..].copy_from_slice(&lsb_r);
            r[..16].copy_from_slice(&chunk);

            res.extend_from_slice(&p);
        }

        // Убрать padding (padding_proc2) в последних 16 байтах
        let idx_check_byte = res.len() - 16;
        while res[idx_check_byte] == 0 || res[idx_check_byte] == 128
        {
            res.remove(idx_check_byte);
        }

        res
    }

    /// Режим гаммирования с обратной связью по шифртексту (Cipher Feedback) с входным сообщением
    /// message, представленным срезом байтов, параметром s, представляющем число бит шифрования,
    /// параметром m = 128*z, где z - целое >= 1, а также IV - инициализирующим вектором длины m,
    /// который для каждого нового сообщения должен формироваться новый. Данный метод используется
    /// для шифрования исходного сообщения.
    pub fn cfb_encrypt(&self, message: &[u8], s: usize, z:usize, iv: & Vec<u8>) -> Vec<u8>
    {
        // s - число бит, которые будут шифроваться
        if s < 1 || s > 128
        {
            panic!("S must be <= 128");
        }

        // z - целое для определения длины регистра и размера IV
        if z < 1
        {
            panic!("Z must be >= 1");
        }

        let m = 128*z/8;            // Длина m в байтах
        let mut r = vec![0u8; m]; // Регистр длины m байт

        r.copy_from_slice(iv);

        let mut res:Vec<u8> = vec![];

        let mut c = 0;              // Байт результата
        let mut cur_idx = 0;     // Текущий обрабатываемый бит
        let mut cur_byte = 0;    // Текущий обрабатываемый байт

        // Шифрование сообщения блоками длины s со сдвигом регистра R
        loop
        {
            // Проверка, что все биты обработаны
            if (cur_idx + cur_byte*8) >= message.len()*8 {break;}

            let mut cipher_text_c:Vec<u8> = vec![]; // Используется для занесения в регистр R значения C

            // Сколько осталось отработать бит из s на данный момент
            let mut rem_bits = s;

            // Передача старшей части регистра R
            let ek_r = self.keys.encrypt(&r[(m - 16)..]).unwrap();

            // Зануление младших бит у ek_r (T_s)
            let gamma = Self::msb(&ek_r, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обработка rem_bit = s
            let mut byte_m:u8;      // Байт message
            let mut byte_ctr:u8;    // Байт Ctr

            // Пока остались биты на обработку
            while rem_bits != 0 
            {
                if cur_byte >= message.len() {break;}

                // Если message[cur_byte] = 0101 1100 и cur_idx = 3
                byte_m = message[cur_byte] >> cur_idx; // Зануление младших обработанных битов даст byte = 0000 1011
                byte_m = byte_m << cur_idx;            // Возврат к исходному положению не зануленных бит byte = 0101 1000
                
                // Часть ctr
                byte_ctr = gamma_u8[cur_byte % 16] >> cur_idx;
                byte_ctr = byte_ctr << cur_idx; 

                // Если операция выполняется на нескольких байтах
                if (cur_idx + rem_bits) > 8
                {
                    rem_bits = rem_bits - (8 - cur_idx);

                    // Переход к следующему байту
                    cur_idx = 0;
                    cur_byte += 1;
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2
                    cipher_text_c.push(c);        // Для сдвига регистра R и занесения в сдвинутые биты C
                    res.push(c);                  // Помещение результата в массив
                    c = 0;                        // Обнуление результата нового байта
                }
                // Если операция выполняется на одном байте
                else {
                    // Если message[cur_byte] = 0001 1100 и cur_idx = 3 и s = 2 
                    byte_m = byte_m >> cur_idx;                    // Зануление младших обработанных битов byte = 0000 0011
                    byte_m = byte_m << cur_idx;                    // Возврат к исходному положению byte = 0001 1000
                    byte_m = byte_m << (8 - (cur_idx + rem_bits)); // Зануление старших бит, которые обрабатывать не надо, даст byte = 1100 0000
                    byte_m = byte_m >> (8 - (cur_idx + rem_bits)); // Возврат к исходному положению byte = 0001 100

                    // Часть ctr
                    byte_ctr = byte_ctr >> cur_idx;
                    byte_ctr = byte_ctr << cur_idx;
                    byte_ctr = byte_ctr << (8 - (cur_idx + rem_bits));
                    byte_ctr = byte_ctr >> (8 - (cur_idx + rem_bits)); 
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2 (Если s < 8, то добавляем части предыдущего результата)

                    // Сдвиг индекса обрабатываемого бита
                    if (cur_idx + rem_bits) == 8 
                    {
                        // Если полностью обработан текущий байт
                        cur_byte += 1; 
                        cur_idx = 0;

                        cipher_text_c.push(c);        // Для сдвига регистра R и занесения в сдвинутые биты C
                        res.push(c);
                        c = 0;
                    } 
                    else {
                        cur_idx += rem_bits;
                    };

                    rem_bits -= rem_bits;
                }
            }

            // Сколько байтов и битов сдвиг s
            let byte_shifted = s / 8;
            let bit_shifted = s % 8;
            let len = r.len();

            // Сдвиг регистра R на s бит
            for idx in 0..r.len()
            {
                // Обработка оставшихся байтов, которым нельзя присвоить идущие раньше их
                if (len as i32) - 1 - (idx as i32) - (byte_shifted as i32) < 0
                {
                    if bit_shifted != 0 {r[len - 1 - idx] = r[len - 1 - idx] << bit_shifted;}

                    // Зануление оставшихся байт
                    for i in 0..byte_shifted
                    {
                        r[i] = 0u8;
                    }
                    
                    break;
                }

                // Сдвиг не соседей
                if bit_shifted != 0 && byte_shifted != 0
                {
                    r[idx + byte_shifted] = (r[idx + byte_shifted] << bit_shifted) | (r[idx] >> (8 - bit_shifted));
                }
                // Сдвиг соседей
                else if bit_shifted != 0 && byte_shifted == 0
                {
                    if idx == 0
                    {
                        r[idx] = r[idx] << bit_shifted;
                    }
                    else {
                        r[idx] = (r[idx] << bit_shifted) | (r[idx - 1] >> (8 - bit_shifted));
                    }
                }
                // Только перенос байтов
                else {
                    r[idx + byte_shifted] = r[idx];
                }
            } 

            // Занесение C в регистр R
            for elem in 0..cipher_text_c.len()
            {
                r[elem] = r[elem] | cipher_text_c[elem];
            }
        }

        res
    }

    /// Режим гаммирования с обратной связью по шифртексту (Cipher Feedback) с входным сообщением
    /// message, представленным срезом байтов, параметром s, представляющем число бит шифрования,
    /// параметром m = 128*z, где z - целое >= 1, а также IV - инициализирующим вектором длины m,
    /// который для каждого нового сообщения должен формироваться новый. Данный метод используется для 
    /// расшифрования шифротекса.
    pub fn cfb_decrypt(&self, message: &[u8], s: usize, z:usize, iv: & Vec<u8>) -> Vec<u8>
    {
        // s - число бит, которые будут шифроваться
        if s < 1 || s > 128
        {
            panic!("S must be <= 128");
        }

        // z - целое для определения длины регистра и размера IV
        if z < 1
        {
            panic!("Z must be >= 1");
        }

        let m = 128*z/8;            // Длина m в байтах
        let mut r = vec![0u8; m]; // Регистр длины m байт

        r.copy_from_slice(iv);

        let mut res:Vec<u8> = vec![];

        let mut c = 0;              // Байт результата
        let mut p = 0;             // Исходный шифротекст
        let mut cur_idx = 0;     // Текущий обрабатываемый бит
        let mut cur_byte = 0;    // Текущий обрабатываемый байт

        // Шифрование сообщения блоками длины s со сдвигом регистра R
        loop
        {
            // Проверка, что все биты обработаны
            if (cur_idx + cur_byte*8) >= message.len()*8 {break;}

            let mut cipher_text_c:Vec<u8> = vec![]; // Используется для занесения в регистр R значения C

            // Сколько осталось отработать бит из s на данный момент
            let mut rem_bits = s;

            // Передача старшей части регистра R
            let ek_r = self.keys.encrypt(&r[(m - 16)..]).unwrap();

            // Зануление младших бит у ek_r (T_s)
            let gamma = Self::msb(&ek_r, s);
            let gamma_u8: &[u8; 16] = gamma[..].try_into().unwrap();

            // Обработка rem_bit = s
            let mut byte_m:u8;      // Байт message
            let mut byte_ctr:u8;    // Байт Ctr

            // Пока остались биты на обработку
            while rem_bits != 0 
            {
                if cur_byte >= message.len() {break;}

                // Если message[cur_byte] = 0101 1100 и cur_idx = 3
                byte_m = message[cur_byte] >> cur_idx; // Зануление младших обработанных битов даст byte = 0000 1011
                byte_m = byte_m << cur_idx;            // Возврат к исходному положению не зануленных бит byte = 0101 1000
                
                // Часть ctr
                byte_ctr = gamma_u8[cur_byte % 16] >> cur_idx;
                byte_ctr = byte_ctr << cur_idx; 

                // Если операция выполняется на нескольких байтах
                if (cur_idx + rem_bits) > 8
                {
                    rem_bits = rem_bits - (8 - cur_idx);

                    // Переход к следующему байту
                    cur_idx = 0;
                    cur_byte += 1;
                    
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2
                    p = p | byte_m;
                    cipher_text_c.push(p);        // Для сдвига регистра R и занесения в сдвинутые биты C
                    res.push(c);                  // Помещение результата в массив
                    c = 0;                        // Обнуление результата нового байта
                    p = 0;
                }
                // Если операция выполняется на одном байте
                else {
                    // Если message[cur_byte] = 0001 1100 и cur_idx = 3 и s = 2 
                    byte_m = byte_m >> cur_idx;                    // Зануление младших обработанных битов byte = 0000 0011
                    byte_m = byte_m << cur_idx;                    // Возврат к исходному положению byte = 0001 1000
                    byte_m = byte_m << (8 - (cur_idx + rem_bits)); // Зануление старших бит, которые обрабатывать не надо, даст byte = 1100 0000
                    byte_m = byte_m >> (8 - (cur_idx + rem_bits)); // Возврат к исходному положению byte = 0001 100

                    // Часть ctr
                    byte_ctr = byte_ctr >> cur_idx;
                    byte_ctr = byte_ctr << cur_idx;
                    byte_ctr = byte_ctr << (8 - (cur_idx + rem_bits));
                    byte_ctr = byte_ctr >> (8 - (cur_idx + rem_bits)); 
                    
                    p = p | byte_m;
                    c = c | (byte_m ^ byte_ctr);  // Суммирование по модулю 2 (Если s < 8, то добавляем части предыдущего результата)

                    // Сдвиг индекса обрабатываемого бита
                    if (cur_idx + rem_bits) == 8 
                    {
                        // Если полностью обработан текущий байт
                        cur_byte += 1; 
                        cur_idx = 0;

                        cipher_text_c.push(p);        // Для сдвига регистра R и занесения в сдвинутые биты C
                        res.push(c);
                        c = 0;
                        p = 0;
                    } 
                    else {
                        cur_idx += rem_bits;
                    };

                    rem_bits -= rem_bits;
                }
            }

            // Сколько байтов и битов сдвиг s
            let byte_shifted = s / 8;
            let bit_shifted = s % 8;
            let len = r.len();

            // Сдвиг регистра R на s бит
            for idx in 0..r.len()
            {
                // Обработка оставшихся байтов, которым нельзя присвоить идущие раньше их
                if (len as i32) - 1 - (idx as i32) - (byte_shifted as i32) < 0
                {
                    if bit_shifted != 0 {r[len - 1 - idx] = r[len - 1 - idx] << bit_shifted;}

                    // Зануление оставшихся байт
                    for i in 0..byte_shifted
                    {
                        r[i] = 0u8;
                    }
                    
                    break;
                }

                // Сдвиг не соседей
                if bit_shifted != 0 && byte_shifted != 0
                {
                    r[idx + byte_shifted] = (r[idx + byte_shifted] << bit_shifted) | (r[idx] >> (8 - bit_shifted));
                }
                // Сдвиг соседей
                else if bit_shifted != 0 && byte_shifted == 0
                {
                    if idx == 0
                    {
                        r[idx] = r[idx] << bit_shifted;
                    }
                    else {
                        r[idx] = (r[idx] << bit_shifted) | (r[idx - 1] >> (8 - bit_shifted));
                    }
                }
                // Только перенос байтов
                else {
                    r[idx + byte_shifted] = r[idx];
                }
            } 

            // Занесение C в регистр R
            for elem in 0..cipher_text_c.len()
            {
                r[elem] = r[elem] | cipher_text_c[elem];
            }
        }

        res
    }
}

#[cfg(test)]
mod tests
{
    use crate::algorithms::{hex_to_bytes, random_vec};
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_cmac()
    {
        let mut r = hex_to_bytes("94bec15e269cf1e506f02b994c0a8ea0");
        r.reverse();

        // КОД ИЗ ФУНКЦИИ CMAC::generate_keys()
        // В_128= 0^128 | 10000111
        let mut b: [u8; 16] = [0; 16];
        b[0] = 135;
        
        let mut k1:[u8; 16] = [0; 16];
        let mut k2:[u8; 16] = [0; 16];

        // R << 1
        for idx in 0..16
        {
            if idx == 15
            {
                k1[0] = r[0] << 1;
            }
            else {
                k1[15 - idx] = (r[15 - idx] << 1) | (r[15 - idx - 1] >> 7);
            }
        }

        // MSB_1(R) != 0
        if (r[15] & 0b1000_0000) != 0
        {
            k1 = sum_mod2(&k1, &b);
        }

        // K1 << 1
        for idx in 0..16
        {
            if idx == 15
            {
                k2[0] = k1[0] << 1;
            }
            else {
                k2[15 - idx] = (k1[15 - idx] << 1) | (k1[15 - idx - 1] >> 7);
            }
        }

        // MSB_1(K1) != 0
        if (k1[15] & 0b1000_0000) != 0
        {
            k2 = sum_mod2(&k2, &b);
        }

        let k1_gost = hex_to_bytes("297d82bc4d39e3ca0de0573298151dc7");
        let k2_gost = hex_to_bytes("52fb05789a73c7941bc0ae65302a3b8e");
        
        k1.reverse();
        k2.reverse();

        assert_eq!(k1.to_vec(), k1_gost);
        assert_eq!(k2.to_vec(), k2_gost);

        // Все части сообщения разбитые по 128 бит
        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        // Формирование последовательного сообщения
        let mut p: Vec<u8> = vec![];
        p.extend(&p1);
        p.extend(&p2);
        p.extend(&p3);
        p.extend(&p4);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();
        k1.reverse();
        k2.reverse();

        let cmac = CMAC{k, k1, k2};

        let mut res = cmac.cmac(&p, 64).unwrap();
        res.reverse();

        let correct_res = hex_to_bytes("336f4d296059fbe3");

        assert_eq!(res, correct_res);
    }

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

    #[test]
    fn test_ctr_encrypt_decrypt_gost()
    {
        // IV - initalizing vector
        let mut iv_str = hex_to_bytes("1234567890abcef0");
        iv_str.reverse();

        let mut iv: [u8; 8] = [0; 8];
        iv.copy_from_slice(&iv_str);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        // Все части сообщения разбитые по 128 бит
        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        // Формирование последовательного сообщения
        let mut p: Vec<u8> = vec![];
        p.extend(&p1);
        p.extend(&p2);
        p.extend(&p3);
        p.extend(&p4);
        
        // Формирование итерационных ключей
        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        // Шифрование
        let res = kuz_ecb.ctr_crypt(&p, 128, &iv);


        // Правильные значения шифротекста
        let mut c1 = hex_to_bytes("f195d8bec10ed1dbd57b5fa240bda1b8");
        c1.reverse();
        let mut c2 = hex_to_bytes("85eee733f6a13e5df33ce4b33c45dee4");
        c2.reverse();
        let mut c3 = hex_to_bytes("a5eae88be6356ed3d5e877f13564a3a5");
        c3.reverse();
        let mut c4 = hex_to_bytes("cb91fab1f20cbab6d1c6d15820bdba73");
        c4.reverse();

        assert_eq!(res[0..16], c1);
        assert_eq!(res[16..32], c2);
        assert_eq!(res[32..48], c3);
        assert_eq!(res[48..], c4);

        // Расшифрование
        let decrypt_res = kuz_ecb.ctr_crypt(&res, 128, &iv);

        assert_eq!(decrypt_res[0..16], p1);
        assert_eq!(decrypt_res[16..32], p2);
        assert_eq!(decrypt_res[32..48], p3);
        assert_eq!(decrypt_res[48..], p4);
    }

    #[test]
    fn test_ctr_encrypt_decrypt_any_s()
    {
        // IV - initalizing vector
        let mut iv_str = hex_to_bytes("1234567890abcef0");
        iv_str.reverse();

        let mut iv: [u8; 8] = [0; 8];
        iv.copy_from_slice(&iv_str);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        // Формирование итерационных ключей
        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        let mut p = hex_to_bytes("1337abcdefabababaabababababbababbbbbbababa");
        p.reverse();

        // Проверка всего диапазона s от 1 до 128
        for s in 1..129
        {
            // Шифрование
            let res_encrypt = kuz_ecb.ctr_crypt(&p, s, &iv);
            let res_decrypt = kuz_ecb.ctr_crypt(&res_encrypt, s, &iv);

            assert_eq!(p, res_decrypt);
        }
    }

    #[test]
    fn test_ofb_encrypt_decrypt()
    {
        // Все части сообщения разбитые по 128 бит
        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        // Формирование последовательного сообщения
        let mut p: Vec<u8> = vec![];
        p.extend(&p1);
        p.extend(&p2);
        p.extend(&p3);
        p.extend(&p4);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        // Формирование итерационных ключей
        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        let mut iv = hex_to_bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819");
        iv.reverse();

        // Шифрование
        let res = kuz_ecb.ofb_crypt(&p, 128, 2, &iv);

        // Правильные значения шифротекста
        let mut c1 = hex_to_bytes("81800a59b1842b24ff1f795e897abd95");
        c1.reverse();
        let mut c2 = hex_to_bytes("ed5b47a7048cfab48fb521369d9326bf");
        c2.reverse();
        let mut c3 = hex_to_bytes("66a257ac3ca0b8b1c80fe7fc10288a13");
        c3.reverse();
        let mut c4 = hex_to_bytes("203ebbc066138660a0292243f6903150");
        c4.reverse();

        assert_eq!(res[0..16], c1);
        assert_eq!(res[16..32], c2);
        assert_eq!(res[32..48], c3);
        assert_eq!(res[48..], c4);

        let decrypt_res = kuz_ecb.ofb_crypt(&res, 128, 2, &iv);

        assert_eq!(decrypt_res[0..16], p1);
        assert_eq!(decrypt_res[16..32], p2);
        assert_eq!(decrypt_res[32..48], p3);
        assert_eq!(decrypt_res[48..], p4);

        // Тестирование для разных параметров s, z, iv
        for s in 1..128
        {
            for z in 1..4
            {
                let iv = random_vec(z*16); // Генерация случайного IV

                // Шифрование
                let res = kuz_ecb.ofb_crypt(&p, s, z, &iv);
                
                // Расшифрование
                let decrypt_res = kuz_ecb.ofb_crypt(&res, s, z, &iv);

                assert_eq!(decrypt_res, p);
            }
        }
    }

    #[test]
    fn test_cbc_encrypt_decrypt()
    {
        // Все части сообщения разбитые по 128 бит
        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        // Формирование последовательного сообщения
        let mut p: Vec<u8> = vec![];
        p.extend(&p1);
        p.extend(&p2);
        p.extend(&p3);
        p.extend(&p4);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        // Формирование итерационных ключей
        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        let mut iv = hex_to_bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819");
        iv.reverse();

        let res = kuz_ecb.cbc_encrypt(&p, 2, &iv);

        // Правильные значения шифротекста
        let mut c1 = hex_to_bytes("689972d4a085fa4d90e52e3d6d7dcc27");
        c1.reverse();
        let mut c2 = hex_to_bytes("2826e661b478eca6af1e8e448d5ea5ac");
        c2.reverse();
        let mut c3 = hex_to_bytes("fe7babf1e91999e85640e8b0f49d90d0");
        c3.reverse();
        let mut c4 = hex_to_bytes("167688065a895c631a2d9a1560b63970");
        c4.reverse();

        assert_eq!(res[0..16], c1);
        assert_eq!(res[16..32], c2);
        assert_eq!(res[32..48], c3);
        assert_eq!(res[48..], c4);

        let res_decrypt = kuz_ecb.cbc_decrypt(&res, 2, &iv);

        assert_eq!(res_decrypt[0..16], p1);
        assert_eq!(res_decrypt[16..32], p2);
        assert_eq!(res_decrypt[32..48], p3);
        assert_eq!(res_decrypt[48..], p4);

        // Проверка для случайных IV и z
        for z in 1..4
        {
            let iv = random_vec(16 * z);
            let result_random_iv = kuz_ecb.cbc_encrypt(&p, z, &iv);
            let result_random_iv_decrypt = kuz_ecb.cbc_decrypt(&result_random_iv, z, &iv);

            assert_eq!(p, result_random_iv_decrypt);
        }
    }

    #[test]
    fn test_cfb_encrypt_decrypt()
    {
        // Все части сообщения разбитые по 128 бит
        let mut p1 = hex_to_bytes("1122334455667700ffeeddccbbaa9988");
        p1.reverse();
        let mut p2 = hex_to_bytes("00112233445566778899aabbcceeff0a");
        p2.reverse();
        let mut p3 = hex_to_bytes("112233445566778899aabbcceeff0a00");
        p3.reverse();
        let mut p4 = hex_to_bytes("2233445566778899aabbcceeff0a0011");
        p4.reverse();

        // Формирование последовательного сообщения
        let mut p: Vec<u8> = vec![];
        p.extend(&p1);
        p.extend(&p2);
        p.extend(&p3);
        p.extend(&p4);

        // K - начальный ключ для формирования итерационных
        let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        k.reverse();

        // Формирование итерационных ключей
        let mut kuz_ecb = CipherModes::new();
        kuz_ecb.keys.keys = Kuznechik::key_generate_with_precopmuted_key(&k);

        let mut iv = hex_to_bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819");
        iv.reverse();

        let res_encrypt = kuz_ecb.cfb_encrypt(&p, 128, 2, &iv);

        // Правильные значения шифротекста
        let mut c1 = hex_to_bytes("81800a59b1842b24ff1f795e897abd95");
        c1.reverse();
        let mut c2 = hex_to_bytes("ed5b47a7048cfab48fb521369d9326bf");
        c2.reverse();
        let mut c3 = hex_to_bytes("79f2a8eb5cc68d38842d264e97a238b5");
        c3.reverse();
        let mut c4 = hex_to_bytes("4ffebecd4e922de6c75bd9dd44fbf4d1");
        c4.reverse();

        assert_eq!(res_encrypt[0..16], c1);
        assert_eq!(res_encrypt[16..32], c2);
        assert_eq!(res_encrypt[32..48], c3);
        assert_eq!(res_encrypt[48..], c4);

        let res_decrypt = kuz_ecb.cfb_decrypt(&res_encrypt, 128, 2, &iv);

        assert_eq!(res_decrypt[0..16], p1);
        assert_eq!(res_decrypt[16..32], p2);
        assert_eq!(res_decrypt[32..48], p3);
        assert_eq!(res_decrypt[48..], p4);

        // Тестирование для разных параметров s, z, iv
        for s in 1..128
        {
            for z in 1..4
            {
                let iv = random_vec(z*16); // Генерация случайного IV

                // Шифрование
                let res = kuz_ecb.cfb_encrypt(&p, s, z, &iv);
                
                // Расшифрование
                let decrypt_res = kuz_ecb.cfb_decrypt(&res, s, z, &iv);

                assert_eq!(decrypt_res, p);
            }
        }
    }
}
