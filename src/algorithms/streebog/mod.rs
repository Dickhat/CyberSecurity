pub mod consts;
use crate::algorithms::hex_to_bytes;
use crate::algorithms::{sum_mod2_wo, sum_mod2, print_bytes};

// Получить мощность сообщения в формате [u8; 64]
fn power_to_u64(rem: u128) -> [u8; 64]
{
    let mut m_power = [0u8; 64];
    let rem_b = rem.to_le_bytes();
    m_power[..rem_b.len()].copy_from_slice(&rem_b);
    m_power
}

// Умножение с матрицей A
fn mul_matrice(b: [u8; 8]) -> [u8; 8]
{
    let mut out: [u8; 8] = [0; 8];

    for (n_byte, byte) in b.iter().enumerate()
    {
        let mut cur_bit: u8 = 1;
        for n_bit in 0..8
        {
            
            if (byte & cur_bit) != 0
            {
                let row_u64 = consts::A[63 - (n_byte * 8 + n_bit)];
                let row_bytes = row_u64.to_ne_bytes();
                out = sum_mod2(&out, & row_bytes); // Берем строку матрицы А в формате [u8; 8], изначально u64
            }

            cur_bit <<= 1;
        }
    }

    out
}

// Последовательность операций, выполняемых в порядке: s, p, l
fn lps(v: [u8; 64]) -> [u8; 64]
{
    let mut res: [u8; 64] = [0; 64];

    //S - Добавить тест
    for index in 0..64 as usize
    {
        res[index] = consts::P[v[index] as usize];
    }
    
    let src = res;
    //P - Добавить тест
    for index in 0..64 as usize
    {
        res[index] = src[consts::T[index] as usize];
    }

    //L - Добавить тест
    for index in 0..8 as usize
    {
        let offset = 8*index;
        let slice: [u8; 8] = res[offset..(offset + 8)].try_into().unwrap();
        // По 8 байт обработка
        res[offset..(offset + 8)].copy_from_slice(&mul_matrice(slice)); 
    }

    res
}

// Функция сжатия
fn gn(h: & [u8; 64], m: & [u8; 64], n: & [u8; 64]) -> [u8; 64]
{
    let mut k: [u8; 64];
    let mut x: [u8; 64] = [0; 64];

    //K_1 = LPS(h sum_mod2 N)
    k = lps(sum_mod2(h, n)); 
    
    // Для первого действия LPS(K1 sum_mod2 M)
    x.clone_from_slice(m);  

    // Е(К, m) = X[K_13]LPSX[K_12]...LPSX[K_1](m).
    for n_iter in 0..12 as usize
    {
        x = lps(sum_mod2(&k, &x));   // На LPSX[K2]LPSX[K1](m)

        // println!("");
        // println!("K_{} = ", n_iter + 1);
        // print_bytes(&k);
        // println!("\nLSPX[K{}] = ", n_iter + 1);
        // print_bytes(&x);
        // println!("");

        // K_(i+1) = LPS(K_i sum_mod2 C_i)
        k = lps(sum_mod2(&k, &consts::C[n_iter]));
    }

    x = sum_mod2(&k, &x); // X[K_13]
    x = sum_mod2(&x, h);  // E mod_sum2 h
    x = sum_mod2(&x, m);  // E mod_sum2 h mod_sum2 m

    //print_bytes(&x);

    x
}

/// Хэширование Стрибог. Обеспечивает получение хэш-кода по message произвольной
/// длины, представляемой срезом байтов. Длина хэш-кода задается параметром bit_length,
/// где допустимыми являются значения 256/512. При некорректном значение вернет строковую
/// ошибку. При корректной работе возвращает вектор байтов хэш-кода.
pub fn streebog(message: &[u8], bit_length: u16) -> Result<Vec<u8>, String>
{
    if bit_length != 256 && bit_length != 512
    {
        return Err("Bit length must be 256 or 512\n".to_string());
    }

    // Этап 1: Присваивание начальных значений
    let mut h: [u8; 64];

    // 00000000 для 512 и 00000001 для 256
    if bit_length == 256 {h = [1; 64];}
    else {h = [0; 64];}
    
    let mut n: [u8; 64] = [0; 64];
    let mut sigma: [u8; 64] = [0; 64];
    let mut m: [u8; 64] = [0; 64];

    let mut count512 = 0; // Шаг по исходному сообщение, если оно >= 512

    // Этап 2: Проверка длины сообщения
    while (message.len() - count512 * 64) * 8  >= 512
    {
        // Значение 512 в формате [u8; 64]
        let mut t512: [u8; 64] = [0; 64];
        t512[1] = 2u8;
        
        // Шаг 2.2: получение подвектора длины 512
        m.copy_from_slice(&message[count512*64..count512 + 64]);
        
        h = gn(&h, &m, &n);                          // Шаг 2.3: h := gn(h, m);
        n = sum_mod2_wo(&n, &t512);      // Шаг 2.4: N := Vec512(lnt512(N) sum_mod2 512);
        sigma = sum_mod2_wo(&sigma, &m); // Шаг 2.5: sigma := Vec512(lnt512(sigma) sum_mod2 Int512(m));
        
        count512 += 1;
    }

    // Этап 3: Итерационные вычисление хэш-кода
    // Шаг 3.1: Дополнение нулями
    m = [0; 64];
    m[..(message.len() - count512 * 64)].copy_from_slice(&message[count512*64..]);
    m[message.len() - count512 * 64] = 1u8;

    h = gn(&h, &m, &n);                             // Шаг 3.2 h := gn(h, m);

    // Мощность сообщения M
    let m_len = 8 * (message.len() - count512 * 64) as u128;

    // Шаг 3.3 N := Vec512(lnt512(N) sum_mod2 |M|);
    n = sum_mod2_wo(&n, &power_to_u64(m_len));
    
    sigma = sum_mod2_wo(&sigma, &m);     // Шаг 3.4 Sigma := Vec512(lnt512(Sigma) sum_mod2 lnt512(m));
    h = gn(&h, &n, &[0; 64]);                   // Шаг 3.5 h := g0(h, N);

    // print!("N = ");
    // print_bytes(&n);
    // println!();
    // print!("Sigma = ");
    // print_bytes(&sigma);
    // println!();
    // print!("h = ");
    // print_bytes(&h);
    // println!();
    
    // Шаг 3.6: Выбор длины хэша
    h = gn(&h, &sigma, &[0; 64]);

    if bit_length == 256 {return Ok(h[32..].to_vec());}

    // Шаг 3.7: Возврат хэша
    return Ok(h.to_vec());
}

#[cfg(test)]
mod tests{
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::algorithms::hex_to_bytes;

    #[test]
    fn test_streebog512_message_less_512() -> Result<(), String>
    {
        let mut hash_true: Vec<u8> = hex_to_bytes("486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b");
        let mut message = hex_to_bytes("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130");
        
        hash_true.reverse();
        message.reverse();

        let hash: Vec<u8> = streebog(&message, 512)?;

        assert_eq!(hash_true, hash);

        Ok(())
    }

    #[test]
    fn test_streebog512_message_greater_512() -> Result<(), String>
    {
        let mut hash_true: Vec<u8> = hex_to_bytes("28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e");
        let mut message: Vec<u8> = hex_to_bytes("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1");

        hash_true.reverse();
        message.reverse();

        let hash: Vec<u8> = streebog(&message, 512)?;

        assert_eq!(hash_true, hash);

        Ok(())
    }

    #[test]
    fn test_streebog256_message_less_512() -> Result<(), String>
    {
        let mut hash_true: Vec<u8> = hex_to_bytes("00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d");
        let mut message: Vec<u8> = hex_to_bytes("323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130");

        hash_true.reverse();
        message.reverse();

        let hash: Vec<u8> = streebog(&message, 256)?;

        assert_eq!(hash_true, hash);

        Ok(())
    }

    #[test]
    fn test_streebog256_message_greater_512() -> Result<(), String>
    {
        let mut hash_true: Vec<u8> = hex_to_bytes("508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d");
        let mut message: Vec<u8> = hex_to_bytes("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1");

        hash_true.reverse();
        message.reverse();

        let hash: Vec<u8> = streebog(&message, 256)?;

        assert_eq!(hash_true, hash);

        Ok(())
    }
}