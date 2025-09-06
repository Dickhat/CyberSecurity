use crypto_bigint::{rand_core::OsRng, Integer, NonZero, Random, Uint, Zero, U256, U512};
use crypto_primes::RandomPrimeWithRng;

#[derive(Debug)]
pub struct RsaData
{
    p: U256, // primary number one
    q: U256, // primary number two
    n: U512, // modulus
    public_key: U512, // e - public exponent
    private_key: U512,// d - private exponent
}

impl RsaData
{
    // fn modpow(mut base: Uint<LIMBS>, mut exp: Uint<LIMBS>, modulus: Uint<LIMBS>) -> Uint<LIMBS> {
    //     let mut result = Uint::<LIMBS>::ONE;
    //     let modulus_nz = NonZero::new(modulus).expect("modulus must be nonzero");

    //     while exp > Uint::<LIMBS>::ZERO {
    //         if exp.is_odd().into() {
    //             result = result.mul_mod(&base, &modulus_nz);
    //         }
            
    //         base = base.mul_mod(&base, &modulus_nz);

    //         exp >>= 1;
    //     }
    //     result
    // }

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

   pub fn get_bpn() -> (U256, U256)
    {
        let mut p;
        let mut q;

        // p = Uint::<LIMBS>::random(&mut OsRng);
        // q = Uint::<LIMBS>::random(&mut OsRng);
        
        // RsaData::bpn_check(p);
        // RsaData::bpn_check(q);
        
        p = crypto_primes::generate_prime(256);
        q = crypto_primes::generate_prime(256);

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

    fn extended_gcd(a: U512, b: U512) -> (U512, U512, U512) {
        if b == U512::ZERO {
            (a, U512::ONE, U512::ZERO)
        } else {
            let (g, x1, y1) = Self::extended_gcd(b, a % b);
            
            let prod = (a / b) * y1;

            let y = if x1 >= prod {x1 - prod}
                             else {x1.wrapping_sub(&prod).wrapping_add(&a)};
            
            (g, y1, y)
        }
    }

    fn secret_exp(e:U512, phi_n:U512) -> U512
    {
        let (g, d, _) = Self::extended_gcd(e, phi_n);
        d
    }

    pub fn rsa_512() -> Result<RsaData, String>
    {
        let (p, q) = RsaData::get_bpn();
        println!("p = {p:?}, \nq = {q:?}");

        let q_minus_one = q - U256::ONE;
        let phi_n: U512 = (p - U256::ONE).widening_mul(&q_minus_one);

        // Открытая эскопнента
        let mut temp:U256 = crypto_primes::generate_prime(256);
        let mut e:U512 = (U256::ONE).widening_mul(&temp);

        while e > phi_n || !Self::coprime(phi_n, e)
        {
            temp = crypto_primes::generate_prime(256);
            e = (U256::ONE).widening_mul(&temp);
        }

        let d = Self::secret_exp(e, phi_n);
        
        println!("n = {phi_n:?} \ne = {e:?} \nd = {d:?}");

        Ok(Self{p, q, n:phi_n, public_key:e, private_key:d})
    }
}

// impl RsaData<U256> {
//     // fn generate() -> Self
//     // {
//     //     let p:U256 = crypto_bigint::U256::random(&mut OsRng);
//     //     let q:U256= crypto_bigint::U256::random(&mut OsRng);
        
        
//     //     Self { p: (), q: (), n: (), public_key: (), private_key: () }
//     // }

//     // Miller-Rabin test
//     fn bpn_check(number:U256) -> bool
//     {
//         let mut s:U256 = U256::ZERO;
//         let mut d:U256 = number - U256::ONE;

//         // Получаем s и d из выражения n - 1 = (2^s)*d
//         while d.is_even().into()
//         {
//             s += U256::ONE;
//             d = d.shr(1);
//         }

//         // Расчет значения ⌊2(ln_number)^2⌋ в виде floor(pow(ln2/lnE,2))
//         // ln2
//         let log2_n  = if number.bits() > 0 {
//             (number.bits() - 1) as f64
//         } else {
//             0 as f64
//         };

//         let ln_n = log2_n / std::f64::consts::LOG2_E;
//         let floor_ln_n = U256::from((2.0*ln_n.powi(2)).floor() as u128);

//         let min:U256 = if number - U256::ONE - U256::ONE < floor_ln_n
//         {
//             number - U256::ONE - U256::ONE
//         }
//         else {
//             floor_ln_n
//         };

//         let mut x:U256;
//         let mut y:U256;

//         let mut a:U256 = U256::from(2u32);
        
//         // for all a in the range [2, min(n − 2, ⌊2(ln_number)^2⌋)]:
//         while a < min
//         {
//             // x ← a^d mod n
//             let mut i:U256 = U256::ZERO;
//             let mut temp_x:U256 = a % number;

//             // Возведение в степень d - 1 раз
//             while i < d - U256::ONE
//             {
//                 temp_x = temp_x * a % number;

//                 i += U256::ONE;
//             }

//             x = temp_x;

//             let mut i:U256 = U256::ZERO;

//             y = x;

//             while i < s
//             {
//                 // y = x^2 mod number;
//                 y = x % number;
//                 y = y * x % number;

//                 if y == U256::ONE && x != U256::ONE && x != (number - U256::ONE) {return false;}
                
//                 x = y;

//                 i += U256::ONE;
//             }

//             // Уточнить про ситуацию неинициализированного y при s = 0
//             if y != U256::ONE {return false;}

//             a += U256::ONE
//         }

//         return true;
//     }
// }

// impl RsaData<U512> {
    
// }
// impl RsaData<U1024> {
    
// }
// impl RsaData<U2048> {
    
// }

// impl RsaData<U4096> {
    
// }

// impl RsaData<U8192> {
    
// }

// impl RsaData<U16384> {
    
// }

// impl RsaData<U32768> {
    
// }

// enum Keys
// {
//     Type_U256 {
//         public_key: crypto_bigint::U256,
//         private_key: crypto_bigint::U256,
//     },
//     Type_U512 {
//         public_key: crypto_bigint::U512,
//         private_key: crypto_bigint::U512,
//     },
//     Type_U1024 {
//         public_key: crypto_bigint::U1024,
//         private_key: crypto_bigint::U1024,
//     },
//     Type_U2048 {
//         public_key: crypto_bigint::U2048,
//         private_key: crypto_bigint::U2048,
//     },
//     Type_U4096 {
//         public_key: crypto_bigint::U4096,
//         private_key: crypto_bigint::U4096,
//     },
//     Type_U8192 {
//         public_key: crypto_bigint::U8192,
//         private_key: crypto_bigint::U8192,
//     },
//     Type_U16384 {
//         public_key: crypto_bigint::U16384,
//         private_key: crypto_bigint::U16384,
//     },
//     Type_U32768 {
//         public_key: crypto_bigint::U32768,
//         private_key: crypto_bigint::U32768,
//     }
// }

// fn get_bpn<T>() -> (T, T)
// where
//     T: Random
// {
//     let mut p;
//     let mut q;

//     p = T::random(&mut OsRng);
//     q = T::random(&mut OsRng);
    
//     RsaData::bpn_check(p);
//     RsaData::bpn_check(q);
    
//     (p, q)
// }

// pub fn rsa<T>() //-> Result<RsaData<T>, String> //Box<dyn Error>
// where 
//     T: Random
// {
//     let (mut p, mut q) =  get_bpn::<T>(); 

    // if [256, 512, 1024, 2048, 4096, 8192, 16384, 32768].contains(&bits_key)
    // {
    //     match bits_key {
    //         256 => {(p, q) = get_bpn::<U256>();},
    //         512 => {(p, q) = get_bpn::<U512>();},
    //         1024 => {(p, q) = get_bpn::<U1024>();},
    //         2048 => {(p, q) = get_bpn::<U2048>();},
    //         4096 => {(p, q) = get_bpn::<U4096>();},
    //         8192 => {(p, q) = get_bpn::<U8192>();},
    //         16384 => {(p, q) = get_bpn::<U16384>();},
    //         32768 => {(p, q) = get_bpn::<U32768>();},
    //         _ => {return;}
    //     }
    //     //Ok(RsaData { p, q, n, public_key: (), private_key: () })
    // }
    // else {
    //     //return Err("Значение длины ключа может быть следующим: 256, 512, 1024, 2048, 4098, 8192, 16384, 32768".to_string());
    // }
//}