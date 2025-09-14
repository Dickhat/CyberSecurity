#![allow(unused_imports)]
#![allow(dead_code)]
use crypto_bigint::{Constants, Encoding, ConcatMixed};
use crypto_bigint::{rand_core::OsRng, Integer, NonZero, Random, Uint, Zero, U256, U512, U1024, I2048, U16384, U32768};
use crypto_primes::{RandomPrimeWithRng};

use std::fs::File;
use std::path::PathBuf;
use std::io::{self, Read, Write};

use super::hex_to_bytes;

#[derive(Debug)]
pub struct RsaData
{
    pub p: U256, // primary number one
    pub q: U256, // primary number two
    pub n: U512, // modulus
    pub public_key: U512, // e - public exponent
    pub private_key: U512,// d - private exponent
}

impl RsaData
{
    // Быстрое возведение в степень и модуль
    fn modpow(mut base: U512, mut exp: U512, modulus: U512) -> U512 {
        if modulus == U512::ONE
        {
            return U512::ZERO;
        }

        let modulus_nz: NonZero<U512> = NonZero::new(modulus).expect("modulus must be nonzero");
        let mut result: U512 = U512::ONE;
        base = base % modulus;

        while exp > U512::ZERO {
            if exp.is_odd().into() {
                result = result.mul_mod(&base, &modulus_nz);
            }
            
            exp = exp >> 1;
            base = base.mul_mod(&base, &modulus_nz);
        }
        result
    }

    // Запись данных RSA в файл RsaData
    fn stf(data:&RsaData)
    {
        let mut file = File::create("RsaData").unwrap();
        
        writeln!(file, "p = {}", data.p).unwrap();
        writeln!(file, "q = {}", data.q).unwrap();
        writeln!(file, "n = {}", data.n).unwrap();
        writeln!(file, "public_key = {}", data.public_key).unwrap();
        writeln!(file, "private_key = {}", data.private_key).unwrap();
    }

    // Необходимо перепроверить всю функцию
    fn bpn_check(number:U256) -> bool
    {
        let mut s:U256 =  U256::ZERO;
        let mut d:U256 = number - U256::ONE;

        // Получаем s и d из выражения n - 1 = (2^s)*d
        while d.is_even().into()
        {
            s += U256::ONE;
            d = d.shr(1);
        }

        // Расчет значения ⌊2(ln_number)^2⌋ в виде floor(pow(ln2/lnE,2))
        // ln2
        let log2_n  = if number.bits() > 0 {
            (number.bits() - 1) as f64
        } else {
            0 as f64
        };

        let ln_n = log2_n / std::f64::consts::LOG2_E;
        let floor_ln_n = U256::from((2.0*ln_n.powi(2)).floor() as u128);

        let min:U256 = if number - U256::ONE - U256::ONE < floor_ln_n
        {
            number - U256::ONE - U256::ONE
        }
        else {
            floor_ln_n
        };

        let mut x:U256;
        let mut y:U256;

        let mut a:U256 = U256::from(2u32);
        
        // for all a in the range [2, min(n − 2, ⌊2(ln_number)^2⌋)]:
        while a < min
        {
            // x ← a^d mod n
            // x = Self::modpow(a, d, number);

            // Долго и вылетает с переполнением
            let mut i:U256 = U256::ONE;
            let mut temp_x:U256 = a % number;

            // Возведение в степень d - 1 раз
            while i < d
            {
                temp_x = temp_x * a % number;

                i += U256::ONE;
            }

            x = temp_x;

            let mut i:U256 = U256::ZERO;

            y = x;

            while i < s
            {
                // y = x^2 mod number;
                y = x % number;
                y = y * x % number;

                if y == U256::ONE && x != U256::ONE && x != (number - U256::ONE) {return false;}
                
                x = y;

                i += U256::ONE;
            }

            // Уточнить про ситуацию неинициализированного y при s = 0
            if y != U256::ONE {return false;}

            a += U256::ONE
        }

        return true;
    }

    fn get_bpn() -> (U256, U256)
    {
        let p;
        let q;

        // p = Uint::<LIMBS>::random(&mut OsRng);
        // q = Uint::<LIMBS>::random(&mut OsRng);
        
        // RsaData::bpn_check(p);
        // RsaData::bpn_check(q);
        
        p = crypto_primes::generate_prime(256);
        q = crypto_primes::generate_prime(256);

        // println!("p={p:?} \nq={q:?}\n");

        (p, q)
    }

    fn coprime(mut a:U512, mut b:U512) -> bool
    {
        // Евклида Алгоритм
        let mut r = U512::ONE;

        while r != U512::ZERO 
        {
            r = b % a;       
            b = a;
            a = r;   
        }

        if b == U512::ONE {true}
        else {false}
    }

    // Проблема с U512 и I1024/2048
    // fn extended_gcd(mut a:U512, mut b:U512) -> (U512, U512)
    // {
    //     // let mut old_rem = a;
    //     // let mut rem: U1024 = b;

    //     let mut x0 = I2048::ONE;
    //     let mut x1 =  I2048::ZERO;
    //     let mut y0 =  I2048::ZERO;
    //     let mut y1 = I2048::ONE; 

    //     let mut quotient = I2048::ZERO; // Частное
    //     let mut remainder = I2048::ONE; // Остаток

    //     let mut prov:I2048;

    //     let mut rem = U1024::ONE;
    //     let mut old_rem = U1024::ONE;
    //     // d^-1*e mod phi(n) = 1
    //     while rem != U1024::ZERO
    //     {
    //         let nr = NonZero::new(rem).unwrap(); // CtOption -> unwrap (runtime)
    //         let (q, rem) = old_rem.div_rem(&nr); // q: U1024, rem: U1024

    //         quotient = old_rem % rem; 

    //         prov = rem;      
    //         rem = old_rem - quotient.widening_mul(rem);
    //         old_rem = prov;

    //         prov = x1;
    //         x1 = x0 - quotient.widening_mul(x1);
    //         x0 = prov;

    //         prov = y1;
    //         y1 = y0 - quotient.widening_mul(y1);
    //     }

    //     (x0, y0);
    // }

    fn secret_exp(e:U512, phi_n:U512) -> U512
    {
        // let (_, d, _) = Self::extended_gcd(e, phi_n);
        e.inv_mod(&phi_n).unwrap()
    }

    // Генерация ключей длиной 512 бит
    pub fn rsa_512() -> Result<RsaData, String>
    {
        let (p, q) = RsaData::get_bpn();

        let q_minus_one = q - U256::ONE;
        let module: U512 = p.widening_mul(&q);
        let phi_n: U512 = (p - U256::ONE).widening_mul(&q_minus_one);

        // Открытая эскопнента
        let mut e:U512 = U512::from_u64(65537u64);

        let mut temp:U256;
        // Проверка, что она удовлетворяет условиям
        while e > phi_n || !Self::coprime(phi_n, e)
        {
            temp = crypto_primes::generate_prime(256);
            e = (U256::ONE).widening_mul(&temp);
        }

        let d = Self::secret_exp(e, phi_n);
        
        // println!("p = {p:?}, \nq = {q:?}\n n = {module:?} \ne = {e:?} \nd = {d:?}");

        let data = RsaData {p, q, n:module, public_key:e, private_key:d};

        Self::stf(&data);

        Ok(data)
    }

    // Шифрование с дополнением. Старшие 2 байта нулевые, чтобы m < N. Старший 3 байт обозначает 
    // число байт дополнения сообщения до 64 байт.
    // Пример: 00A0000000BACSA...A <- старшие 00, A - число байт дополнения, начало сообщения с байта со значением B. 
    pub fn encryption(&self, message:& String) -> Result<PathBuf, String>
    {
        let path = PathBuf::from("output_encryption");
        let mut file = File::create(&path).unwrap();     // Добавить проверку на создание файла
        let mut buf = [0u8; 64];
        let mut cipher_text:U512;

        // Короткий текст
        if message.len() < 64
        {
            buf[2] = 64 - message.as_bytes().len() as u8; // Число байт дополнения (включая сам этот байт)
            buf[64 - message.as_bytes().len()..].copy_from_slice(message.as_bytes()); // Вставить в конец сообщение

            cipher_text = U512::from_be_slice(&buf);
            cipher_text = Self::modpow(cipher_text, self.public_key, self.n);

            file.write_all(&cipher_text.to_be_bytes()).unwrap();
        }
        
        else {
            let b_message = message.as_bytes();

            // По 60 байт (text < (512 / 8))
            for bytes in b_message.chunks(60)
            {
                buf = [0u8; 64];
                buf[2] = 64 - bytes.len() as u8;                    // Число байт дополнения (включая сам этот байт)
                buf[64 - bytes.len()..].copy_from_slice(bytes); // Вставить в конец сообщение

                cipher_text = U512::from_be_slice(&buf);
                cipher_text = Self::modpow(cipher_text, self.public_key, self.n);

                // Добавить проверку на записанные байты
                file.write_all(&cipher_text.to_be_bytes()).unwrap();
            }
        }

        Ok(path)
    }

    pub fn decryption(&self, message_path:PathBuf) -> Result<PathBuf, String>
    {
        let path = PathBuf::from("output_decrytion");

        // Добавить проверку на создание файла
        let mut file_out = File::create(&path).unwrap();
        let mut file_in = File::open(&message_path).unwrap();
        
        let mut buffer = [0u8; 64];
        let mut text:U512;
        let mut padding:usize;

        loop {
            let n = file_in.read(&mut buffer).unwrap();

            if n == 0 {break;}

            text = U512::from_be_slice(&buffer);
            text = Self::modpow(text, self.private_key, self.n);

            let text_b = text.to_be_bytes();
            padding = 64 - text_b[2] as usize;       // ПРоверить переполнение

            // Добавить проверку на записанные байты
            file_out.write_all(&text_b[64 - padding..]).unwrap(); // Записать текст без дополнения
        }

        Ok(path)
    }
}

#[derive(Debug)]
pub struct RsaDataU32768
{
    pub p: U16384, // primary number one
    pub q: U16384, // primary number two
    pub n: U32768, // modulus
    pub public_key: U32768, // e - public exponent
    pub private_key: U32768,// d - private exponent
}

// Доделать encrypt/decrypt
impl RsaDataU32768 {
    // Проверить на переполнение
    fn mulmod(left: & U32768, rigth: & U32768, modulus: & U32768) -> U32768
    {
        let left_m = *left % *modulus;
        let right_m = *rigth % *modulus;

        (left_m * right_m) % *modulus
    }

    // Быстрое возведение в степень и модуль
    fn modpow(mut base: U32768, mut exp: U32768, modulus: U32768) -> U32768 {
        if modulus == U32768::ONE
        {
            return U32768::ZERO;
        }

        let modulus_nz: NonZero<U32768> = NonZero::new(modulus).expect("modulus must be nonzero");
        let mut result: U32768 = U32768::ONE;
        base = base % modulus;

        while exp > U32768::ZERO {
            if exp.is_odd().into() {
                result = Self::mulmod(& result, & base, & modulus_nz); //.mul_mod(&base, &modulus_nz);
            }
            
            exp = exp >> 1;
            base =  Self::mulmod(& base, & base, & modulus_nz);//base.mul_mod(&base, &modulus_nz);
        }
        result
    }

    // Запись данных RSA в файл RsaData
    fn stf(data:&RsaDataU32768)
    {
        let mut file = File::create("RsaData32768").unwrap();
        
        writeln!(file, "p = {}", data.p).unwrap();
        writeln!(file, "q = {}", data.q).unwrap();
        writeln!(file, "n = {}", data.n).unwrap();
        writeln!(file, "public_key = {}", data.public_key).unwrap();
        writeln!(file, "private_key = {}", data.private_key).unwrap();
    }

    fn get_bpn() -> (U16384, U16384)
    {
        let p;
        let q;

        // p = Uint::<LIMBS>::random(&mut OsRng);
        // q = Uint::<LIMBS>::random(&mut OsRng);
        
        // RsaData::bpn_check(p);
        // RsaData::bpn_check(q);
        
        p = crypto_primes::par_generate_prime(16384, 8); //crypto_primes::generate_prime(16384);
        q = crypto_primes::par_generate_prime(16384, 8); //crypto_primes::generate_prime(16384);
        // println!("p={p:?} \nq={q:?}\n");

        (p, q)
    }

    fn coprime(mut a:U32768, mut b:U32768) -> bool
    {
        // Евклида Алгоритм
        let mut r = U32768::ONE;

        while r != U32768::ZERO 
        {
            r = b % a;       
            b = a;
            a = r;   
        }

        if b == U32768::ONE {true}
        else {false}
    }

    fn secret_exp(e:U32768, phi_n:U32768) -> U32768
    {
        // let (_, d, _) = Self::extended_gcd(e, phi_n);
        e.inv_mod(&phi_n).unwrap()
    }

    // Генерация ключей длиной 32768 бит
    pub fn rsa_32768() -> Result<RsaDataU32768, String>
    {
        let (p, q) = RsaDataU32768::get_bpn();

        let p_wide: U32768 = p.resize();
        let q_wide: U32768 = q.resize();

        // phi_n = (p-1)*(q-1)
        // n = p*q
        let phi_n: U32768 = (p_wide - U32768::ONE) * (q_wide - U32768::ONE); 
        let module: U32768 = p_wide * q_wide;

        // Открытая эскопнента
        let e:U32768 = U32768::from_u64(65537u64);

        // let mut temp:U16384;
        // // Проверка, что она удовлетворяет условиям
        // while e > phi_n || !Self::coprime(phi_n, e)
        // {
        //     temp = crypto_primes::generate_prime(16384);
        //     e = temp.resize();
        // }

        let d = Self::secret_exp(e, phi_n);
        
        // println!("p = {p:?}, \nq = {q:?}\n n = {module:?} \ne = {e:?} \nd = {d:?}");

        let data = RsaDataU32768 {p, q, n:module, public_key:e, private_key:d};

        Self::stf(&data);

        Ok(data)
    }
}


/// Модуль тестов запускать последовательно, так как пишутся результаты в один файл
/// и это может вызвать неправильные результаты и соответственно интепретацию результатов.
/// # Пример
/// ```
/// cargo test -- --test-threads=1
/// ```
#[cfg(test)]
mod tests {
    use core::panic::PanicMessage;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    // Предрассчитанные ключи
    // let p_bytes = hex_to_bytes("E6B42BCB8FAA28DDDC0600AB7AE17DA86C8D380C2D1F8E138190D2BBA693D411");
    // let q_bytes = hex_to_bytes("A23E4E6073B17209E8F56CFBDCAE306C196CEF4DEE779F2B69D74FA51F380731");
    // let n_bytes = hex_to_bytes("923629FB3D61C431E6486B96222C55EA6B5AB23D557DC723185F6632A4A07D39CD68C637A037E74023C8897CAE1D029EE2520741449F0CD0A3B3BC725FD00E41");
    // let pb_bytes = hex_to_bytes("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001");
    // let pvk_bytes = hex_to_bytes("89E0FE11E8BE8B6FAB03DC410614DD2864F870611A7FB40CCA6D1C48E1AA5EAB7314437E27FC2F1A9EBBB965A36B3FB00288F3A25FB50705B9CFC1889BBF1E01");

    // Выполнение RSA шифрования и расшифрования
    // let temp = RsaData{p, q, n, public_key, private_key};
    // let message: String = "Hello fucking WORLD LICK MY ASS".to_string();
    // temp.encryption(message.clone());
    // temp.decryption(message);

    #[test]
    fn test_rsa_short_message_encryption_decryption() -> Result<(), String> {
        let data = RsaData::rsa_512()?;

        let message = "Hello World!!!".to_string();

        let encryption_path = data.encryption(& message)?;
        let decryption_path = data.decryption(encryption_path)?;

        let mut file_in = File::open(decryption_path).unwrap();
        
        let mut text_vec = Vec::new();
        file_in.read_to_end(& mut text_vec).expect("Ошибка чтения файла до конца");

        let text_str = String::from_utf8(text_vec.to_vec()).unwrap();

        assert_eq!(message, text_str);

        Ok(())
    }

    #[test]
    fn test_rsa_long_message_encryption_decryption() -> Result<(), String> {
        let data = RsaData::rsa_512()?;

        let message = "Вино губит телесное здоровье людей, губит умственные способности, губит благосостояние семей и, что всего ужаснее, губит душу людей и их потомство, и, несмотря на это, с каждым годом все больше и больше распространяется употребление спиртных напитков и происходящее от него пьянство. Заразная болезнь захватывает все больше и больше людей: пьют уже женщины, девушки, дети. И взрослые не только не мешают этому отравлению, но, сами пьяные, поощряют их. И богатым, и бедным представляется, что веселым нельзя иначе быть, как пьяным или полупьяным, представляется, что при всяком важном случае жизни: похоронах, свадьбе, крестинах, разлуке, свидании — самое лучшее средство показать свое горе или радость состоит в том, чтобы одурманиться и, лишившись человеческого образа, уподобиться животному. И что удивительнее всего, это то, что люди гибнут от пьянства и губят других, сами не зная, зачем они это делают. В самом деле, если каждый спросит себя, для чего люди пьют, он никак не найдет никакого ответа. Сказать, что вино вкусно, нельзя, потому что каждый знает, что вино и пиво, если они не подслащены, кажутся неприятными для тех, кто их пьет в первый раз. К вину приучаются, как к другому яду, табаку, понемногу, и нравится вино только после того, как человек привыкнет к тому опьянению, которое оно производит. Сказать, что вино полезно для здоровья, тоже никак нельзя теперь, когда многие доктора, занимаясь этим делом, признали, что ни водка, ни вино, ни пиво не могут быть здоровы, потому что питательности в них нет, а есть только яд, который вреден. Сказать, что вино прибавляет силы, тоже , нельзя, потому что не раз и не два, а сотни раз было замечено, что артель пьющая в столько же людей, как и артель непьющая, сработает много меньше. И на сотнях и тысячах людей можно заметить, что люди, пьющие одну воду, сильнее и здоровее тех, которые пьют вино. Говорят тоже, что вино греет, но и это неправда, и всякий знает, что выпивший человек согревается только накоротко, а надолго скорее застынет, чем непьющий. Сказать, что если выпить на похоронах, на крестинах, на свадьбах, при свиданиях, при разлуках, при покупке, продаже, то лучше обдумаешь то дело, для которого собрались,— тоже никак нельзя, потому что при всех таких случаях нужно не одуреть от вина, а с свежей головой обсудить дело. Что важней случай, то трезвей, а не пьяней надо быть. Нельзя сказать и того, чтобы вредно было бросить вино тому, кто привык к нему, потому что мы каждый день видим, как пьющие люди попадают в острог и живут там без вина и только здоровеют. Нельзя сказать и того, чтобы от вина больше веселья было. Правда, что от вина накоротко люди как будто и согреваются и развеселяются, но и то и другое ненадолго. И как согреется человек от вина и еще пуще озябнет, так и развеселится от вина человек и еще пуще сделается скучен. Только стоит зайти в трактир да посидеть, посмотреть на драку, крик, слезы, чтобы понять то, что не веселит вино человека. Нельзя сказать и того, чтобы не вредно было пьянство. Про вред его и телу и душе всякий знает. И что ж? И не вкусно вино, и не питает, и не крепит, и не греет, и не помогает в делах, и вредно телу и душе — и все-таки столько людей его пьют, и что дальше, то больше. Зачем же пьют и губят себя и других людей? «Все пьют и угощают, нельзя же и мне не пить и не угощать»,— отвечают на это многие, и, живя среди пьяных, эти люди точно воображают, что все кругом пьют и угощают. Но ведь это неправда. Если человек вор, то он будет и водиться с ворами, и будет ему казаться, что все воры. Но стоит ему бросить воровство, и станет он водиться с честными людьми и увидит, что не все воры. То же и с пьянством. Не все пьют и угощают. Если бы все пили, так уже не надолго бы оставалось и жизни людям: все бы перемерли; но до этого не допустит бог: и всегда были и теперь есть много и много миллионов людей непьющих и понимающих, что пить или не пить — дело не шуточное. Если сцепились рука с рукой люди пьющие и торгующие вином и наступают на других людей и хотят споить весь мир, то пора и людям разумным понять, что и им надо схватиться рука с рукой и бороться со злом, чтобы их и их детей не споили заблудшие люди. Пора опомниться!".to_string();

        let encryption_path = data.encryption(& message)?;
        let decryption_path = data.decryption(encryption_path)?;

        let mut file_in = File::open(decryption_path).unwrap();
        
        let mut text_vec = Vec::new();
        file_in.read_to_end(& mut text_vec).expect("Ошибка чтения файла до конца");

        let text_str = String::from_utf8(text_vec.to_vec()).unwrap();

        assert_eq!(message, text_str);

        Ok(())
    }
}