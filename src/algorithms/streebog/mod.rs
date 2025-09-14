pub mod consts;

fn print_bytes_hex(bytes: &[u8; 64]) {
    // первая строка: последние 32 байта в обратном порядке
    for b in bytes[32..].iter().rev() {
        print!("{:02x}", b);
    }

    // вторая строка: следующие 20 байт в обратном порядке
    for b in bytes[12..32].iter().rev() {
        print!("{:02x}", b);
    }

    // оставшиеся 12 байт (первые) в обратном порядке
    for b in bytes[..12].iter().rev() {
        print!("{:02x}", b);
    }
}


// Суммирование по модулю 2
fn sum_mod2<const N: usize>(str1: &[u8; N], str2: &[u8; N]) -> [u8; N]
{
    let mut res: [u8; N] = [0; N];

    // Суммирование по модулю 2
    for index in 0..N
    {
        res[index] = str1[index] ^ str2[index];
        
        // println!("{:#018x},", str1[index]);
        // println!("{:#018x},", str2[index]);
        // println!("{:#018x},", res[index]);
    }

    //println!("{res:?}");
    res
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

pub fn lps(v: [u8; 64]) -> [u8; 64]
{
    let mut res: [u8; 64] = [0; 64];

    //S - Добавить тест
    for index in 0..64 as usize
    {
        res[index] = consts::P[v[index] as usize];
    }
    
    // println!("{res:?}");
    let src = res;
    //P - Добавить тест
    for index in 0..64 as usize
    {
        res[index] = src[consts::T[index] as usize];
    }

    // println!("{res:?}");

    //L - Добавить тест
    for index in 0..8 as usize
    {
        let offset = 8*index;
        let slice: [u8; 8] = res[offset..(offset + 8)].try_into().unwrap();
        // По 8 байт обработка
        res[offset..(offset + 8)].copy_from_slice(&mul_matrice(slice)); 
    }

    // println!("{res:?}");

    res
}

// Функция сжатия
fn gN(h: & [u8; 64], m: & [u8; 64], n: & [u8; 64]) -> [u8; 64]
{
    let mut k: [u8; 64] = [0; 64];
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
        // print_bytes_hex(&k);
        // println!("\nLSPX[K{}] = ", n_iter + 1);
        // print_bytes_hex(&x);
        // println!("");

        // K_(i+1) = LPS(K_i sum_mod2 C_i)
        k = lps(sum_mod2(&k, &consts::C[n_iter]));
    }

    x = sum_mod2(&k, &x); // X[K_13]
    x = sum_mod2(&x, h);  // E mod_sum2 h
    x = sum_mod2(&x, m);  // E mod_sum2 h mod_sum2 m

    //print_bytes_hex(&x);

    x
}


pub fn streebog_512(message: &[u8]) -> [u8; 64]
{
    // Этап 1: Присваивание начальных значений
    let mut h: [u8; 64] = [0; 64];
    let n: [u8; 64] = [0; 64];
    let sigma: [u8; 64] = [0; 64];

    let mut m: [u8; 64] = [0; 64];

    // Этап 2: Проверка длины сообщения
    while message.len() * 8 >= 512
    {
        // Укорачивать сообщение (ДОДЕЛАТЬ)
        println!("Message >= 512");
    }

    // Этап 3: Итерационные вычисление хэш-кода
    // Шаг 3.1: Дополнение нулями
    m[64 - message.len()..].copy_from_slice(message);
    m[64 - message.len() - 1] = 1;  // 1 перед сообщением

    m.reverse();

    h = gN(&h, &m, &n);             // Шаг 3.2
    
    h = gN(&h, &m, &[0; 64]);    // Шаг 3.5


    // Шаг 3.6: Выбор длины хэша
    if 256 == 256
    {

    }
    else {
        
    }

    // Шаг 3.7: Возврат хэша
    h
}