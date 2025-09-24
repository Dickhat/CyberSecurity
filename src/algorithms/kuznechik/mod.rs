use std::vec;

use crate::algorithms::{hex_to_bytes, kuznechik::consts::{KUZ_PI, L_VEC}};

pub mod consts;

/// Конечное поле GF(2)[x]/p(x), где р(х) = х^8 + х^7 + х^6 + х + 1 принадлежит GF(2)[x]; 
/// элементы поля F представляются целыми числами, причем элементу z0 + z1•t + ... + z7•t, принадлежащему F, соответствует число z0+ 2•z1 + ...+2•z7,
/// где zi принадлежит {0, 1}, i = 0, 1,..., 7, и t обозначает класс вычетов по модулю р(х), содержащий х;
pub fn mul_gf2_px(elem1: &u8, elem2: &u8) -> u8
{
	let px: u8 = 0b1100_0011; // Для операции XOR. х^8 + х^7 + х^6 + х + 1
	
	let mut a = *elem1;
	let mut b = *elem2;
	let mut res: u8 = 0;

	let mut carry = 0; // Проверка, что степень числа < 8

	for _ in 0..8
	{
		// Младший бит 1 - значит умножаем
		if b & 1 != 0
		{
			res ^= a;
		}

		carry = a & 0x80;
		a <<= 1;	// Сдвиг влево множимого

		if carry != 0
		{
			a ^= px; // Xor множимого, так как степень > 7
		}

		b >>= 1;	// Сдвиг множителя право
	}

	res
}

// linear transformation
fn linear(a: &[u8; 16]) -> u8
{
	let mut res: u8 = 0;

	for (idx, elem) in a.iter().enumerate()
	{
		// Formula (1) page 3 in ГОСТ Р 34.12-2018
		res = res ^ &mul_gf2_px(elem, &L_VEC[idx]);
	}

	res
}

// Formula (2) page 4 in ГОСТ Р 34.12-2018
fn x(k: &[u8; 16], a: &[u8; 16]) -> [u8; 16]
{
	let mut res: [u8; 16] = [0; 16];

	for idx in 0..16
	{
		res[idx] = k[idx] ^ a[idx];
	}

	res
}

// Formula (3) page 4 in ГОСТ Р 34.12-2018
fn s(a: &[u8; 16]) -> [u8; 16]
{
	let mut res: [u8; 16] = [0; 16];

	for idx in 0..16 as usize
	{
		res[idx] = KUZ_PI[a[idx] as usize];
	}

	res
}

// Formula (5) page 4 in ГОСТ Р 34.12-2018
fn r(a: &[u8; 16]) -> [u8; 16]
{
	let mut res: [u8; 16] = [0; 16];

	let l_part = linear(a);

	// l_part||а15, ..., а1
	res[15] = l_part;
	res[..15].copy_from_slice(&a[1..]);
	
	res
}

// Formula (6) page 4 in ГОСТ Р 34.12-2018
fn l(a: &[u8; 16]) -> [u8; 16]
{
	let mut res: [u8; 16] = a.clone();

	for _ in 0..16{
		res = r(&res);
	}

	res
}

// Sequence of operations in order x, s, l 
fn lsx(k: &[u8; 16], a: &[u8; 16]) -> [u8; 16]
{
	let mut res: [u8; 16] = [0; 16];

	res = x(k, a);
	res = s(&res);
	res = l(&res);

	res
}

// Formula (9) page 4 in ГОСТ Р 34.12-2018
fn fk(k: &[u8; 16], a1: &[u8; 16], a0: &[u8; 16]) -> ([u8; 16], [u8; 16])
{
	let mut res: [u8; 16] = [0; 16];

	res = lsx(k, a1);
	res = x(&res, a0);	// Можно использовать X, т.к. оно реализует суммирование mod2

	(res, a1.clone())
}

// Formula (10) page 4 in ГОСТ Р 34.12-2018
fn iterational_constants() -> Vec<[u8; 16]>
{
	let mut c_vec: Vec<[u8; 16]> = vec![];
	let mut value: [u8; 16];

	for i in 1..33 as u8
	{
		value = [0; 16];
		value[0] = i;

		c_vec.push(l(&value));
	}

	c_vec
}

/// Создание ключа длиной 256 бит, а также 10 итерационных ключей
/// Результат: (Ключ_K, вектор_итерационных_ключей)
/// Добавить генерацию случайного ключа K
pub fn key_generate() -> (Vec<u8>, Vec<[u8; 16]>)
{
	let c_vec = iterational_constants();
	
	// Ключ из ГОСТ Р. Возможно после заменить на случайную генерацию
	let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
	k.reverse();

	let mut k_vec: Vec<[u8; 16]> = Vec::with_capacity(10);	// Все итерационные ключи
	
	let mut k1: [u8; 16] = [0; 16];
	k1.copy_from_slice(&k[16..]);
	k_vec.push(k1);

	let mut k2: [u8; 16] = [0; 16];
	k2.copy_from_slice(&k[..16]);
	k_vec.push(k2);

	for i in 1..5 as usize
	{
		// F [С_8(i-1)+8]...F[С_8(i-1)+1](K_2i-1, K_2i)
		for iter in 1..9 as usize
		{
			(k1, k2) = fk(&c_vec[8 * (i - 1) + iter], &k1, &k2);
		}

		// Пушит копию (до 32 байт)
		k_vec.push(k1);
		k_vec.push(k2);
	}

	(k, k_vec)
}

// /// Шифрование M по блокам длины 128
// pub fn encryption()
// {
//     let mut prime1: U512 = generate_prime(512);
//     let mut prime2: U512 = generate_prime(512);

//     let key = key_generate();
// }

// /// Расшифрование M по блокам длины 128
// pub fn decryption()
// {

// }

#[cfg(test)]
mod tests
{
	// Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::algorithms::hex_to_bytes;
	use crate::algorithms::streebog::print_bytes;

	#[test]
	fn test_r_transform()
	{
		// Исходная строка
		let mut a = hex_to_bytes("00000000000000000000000000000100");
		a.reverse();	// litte-endian
		let arr: [u8; 16] = a.clone().try_into().expect("должно быть 16 байт");

		// Правильные ответы
		let mut r1 = hex_to_bytes("94000000000000000000000000000001");
		r1.reverse();
		let mut r2 = hex_to_bytes("a5940000000000000000000000000000");
		r2.reverse();
		let mut r3 = hex_to_bytes("64a59400000000000000000000000000");
		r3.reverse();
		let mut r4 = hex_to_bytes("0d64a594000000000000000000000000");
		r4.reverse();
		
		// Проверки
		let mut res = r(&arr);
		assert_eq!(res.to_vec(), r1);

		res = r(&res);
		assert_eq!(res.to_vec(), r2);

		res = r(&res);
		assert_eq!(res.to_vec(), r3);

		res = r(&res);	
		assert_eq!(res.to_vec(), r4);
	}

	#[test]
	fn test_l_transform()
	{
		// Исходная строка
		let mut a = hex_to_bytes("64a59400000000000000000000000000");
		a.reverse();	// litte-endian
		let arr: [u8; 16] = a.clone().try_into().expect("должно быть 16 байт");

		// Правильные ответы
		let mut l1 = hex_to_bytes("d456584dd0e3e84cc3166e4b7fa2890d");
		l1.reverse();
		let mut l2 = hex_to_bytes("79d26221b87b584cd42fbc4ffea5de9a");
		l2.reverse();
		let mut l3 = hex_to_bytes("0e93691a0cfc60408b7b68f66b513c13");
		l3.reverse();
		let mut l4 = hex_to_bytes("e6a8094fee0aa204fd97bcb0b44b8580");
		l4.reverse();
		
		// Проверки
		let mut res = l(&arr);
		assert_eq!(res.to_vec(), l1);

		res = l(&res);
		assert_eq!(res.to_vec(), l2);

		res = l(&res);
		assert_eq!(res.to_vec(), l3);

		res = l(&res);	
		assert_eq!(res.to_vec(), l4);
	}

	#[test]
	fn test_c_constants()
	{
		let c_vec = iterational_constants();
		let mut c_correct_vec = Vec::with_capacity(8);

		// Правильные ответы
		let mut c1 = hex_to_bytes("6ea276726c487ab85d27bd10dd849401");
		c1.reverse();
		c_correct_vec.push(c1);

		let mut c2 = hex_to_bytes("dc87ece4d890f4b3ba4eb92079cbeb02");
		c2.reverse();
		c_correct_vec.push(c2);

		let mut c3 = hex_to_bytes("b2259a96b4d88e0be7690430a44f7f03");
		c3.reverse();
		c_correct_vec.push(c3);

		let mut c4 = hex_to_bytes("7bcd1b0b73e32ba5b79cb140f2551504");
		c4.reverse();
		c_correct_vec.push(c4);

		let mut c5 = hex_to_bytes("156f6d791fab511deabb0c502fd18105");
		c5.reverse();
		c_correct_vec.push(c5);

		let mut c6 = hex_to_bytes("a74af7efab73df160dd208608b9efe06");
		c6.reverse();
		c_correct_vec.push(c6);

		let mut c7 = hex_to_bytes("c9e8819dc73ba5ae50f5b570561a6a07");
		c7.reverse();
		c_correct_vec.push(c7);

		let mut c8 = hex_to_bytes("f6593616e6055689adfba18027aa2a08");
		c8.reverse();
		c_correct_vec.push(c8);

		// Проверка всех значений
		for elem in 0..8
		{
			assert_eq!(c_vec[elem].to_vec(), c_correct_vec[elem]);
		}
	}

	#[test]
	fn test_fc()
	{
		// Начальные данные
		let c_vec = iterational_constants();

		let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
		k.reverse();

		let mut k1: [u8; 16] = [0; 16];
		k1.copy_from_slice(&k[16..]);

		let mut k2: [u8; 16] = [0; 16];
		k2.copy_from_slice(&k[..16]);

		// Правильные ответы
		let mut correct_results: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(8);

		let mut res_left = hex_to_bytes("c3d5fa01ebe36f7a9374427ad7ca8949");
		let mut res_right = hex_to_bytes("8899aabbccddeeff0011223344556677");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("37777748e56453377d5e262d90903f87");
		res_right = hex_to_bytes("c3d5fa01ebe36f7a9374427ad7ca8949");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("f9eae5f29b2815e31f11ac5d9c29fb01");
		res_right = hex_to_bytes("37777748e56453377d5e262d90903f87");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("e980089683d00d4be37dd3434699b98f");
		res_right = hex_to_bytes("f9eae5f29b2815e31f11ac5d9c29fb01");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("b7bd70acea4460714f4ebe13835cf004");
		res_right = hex_to_bytes("e980089683d00d4be37dd3434699b98f");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("1a46ea1cf6ccd236467287df93fdf974");
		res_right = hex_to_bytes("b7bd70acea4460714f4ebe13835cf004");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("3d4553d8e9cfec6815ebadc40a9ffd04");
		res_right = hex_to_bytes("1a46ea1cf6ccd236467287df93fdf974");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));

		res_left = hex_to_bytes("db31485315694343228d6aef8cc78c44");
		res_right = hex_to_bytes("3d4553d8e9cfec6815ebadc40a9ffd04");
		res_left.reverse();
		res_right.reverse();
		correct_results.push((res_left, res_right));


		// Расчет значений
		let i = 1;

		// F [С_8(i-1)+8]...F[С_8(i-1)+1](K_2i-1, K_2i)
		for iter in 0..8 as usize
		{
			(k1, k2) = fk(&c_vec[8 * (i - 1) + iter], &k1, &k2);
			assert_eq!((k1.to_vec(), k2.to_vec()), correct_results[iter]);
		}
	}

	#[test]
	fn test_iterational_keys()
	{
		// Начальные данные
		let c_vec = iterational_constants();
		let mut k_vec = Vec::with_capacity(10);

		let mut k = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
		k.reverse();

		let mut k1: [u8; 16] = [0; 16];
		k1.copy_from_slice(&k[16..]);
		k_vec.push(k1);

		let mut k2: [u8; 16] = [0; 16];
		k2.copy_from_slice(&k[..16]);
		k_vec.push(k2);

		// Расчет итерационных ключей
		for i in 1..5
		{
			// F [С_8(i-1)+8]...F[С_8(i-1)+1](K_2i-1, K_2i)
			for iter in 0..8 as usize
			{
				(k1, k2) = fk(&c_vec[8 * (i - 1) + iter], &k1, &k2);
			}

			k_vec.push(k1);
			k_vec.push(k2);
		}

		// Правильные ответы
		let mut correct_results: Vec<Vec<u8>> = Vec::with_capacity(10);

		let mut res = hex_to_bytes("8899aabbccddeeff0011223344556677");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("fedcba98765432100123456789abcdef");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("db31485315694343228d6aef8cc78c44");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("3d4553d8e9cfec6815ebadc40a9ffd04");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("57646468c44a5e28d3e59246f429f1ac");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("bd079435165c6432b532e82834da581b");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("51e640757e8745de705727265a0098b1");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("5a7925017b9fdd3ed72a91a22286f984");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("bb44e25378c73123a5f32f73cdb6e517");
		res.reverse();
		correct_results.push(res);

		res = hex_to_bytes("72e9dd7416bcf45b755dbaa88e4a4043");
		res.reverse();
		correct_results.push(res);

		for idx in 0..10
		{
			assert_eq!(k_vec[idx].to_vec(), correct_results[idx]);
		}
	}
}