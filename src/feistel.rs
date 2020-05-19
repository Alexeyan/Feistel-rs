use std::io::prelude::*;
use sha3::{Digest, Sha3_256};

pub trait WriteU32sLE<T> {
    fn write_u32s_le(&mut self, values: &[u32]) -> std::io::Result<usize>;
}

impl<T> WriteU32sLE<T> for T where T : Write {
    fn write_u32s_le(&mut self, values: &[u32]) -> std::io::Result<usize> {
        for value in values {
            let bytes = value.to_le_bytes();
            self.write_all(&bytes)?;
        }
        Ok(values.len() * 4)
    }
}

// The round function in Feistel needs to be a strong PRF. We use sha3, as it is one.
// Note that the round function does not need to be invertible
// This func returns   sha3(subkey||data)[0-len(data)]
fn round_fn(data: &[u8], subkey: &[u8]) -> Vec<u8> {
    // PRF that takes two vectors and produces pseudorandom output.
    // Note that the round function is not part of the Feistel cipher and should be set manually.
    let mut hasher = Sha3_256::new();
    hasher.input(subkey);
    hasher.input(data); 
    let hash = hasher.result().to_vec();
    
    let result: Vec<u8>; 
    if data.len() < hash.len() {
        result = hash[0..data.len()].to_vec(); // Round function needs to be length preserving
    } else if data.len() == hash.len() {
        result = hash;
    } else { // data.len() > hash.len() = We cycle the hash to the desired length
        result = hash.into_iter().cycle().take(data.len()).collect::<Vec<u8>>();
    }
    result
    //result.to_vec()
}

// Feistel encryption function that encrypts a byte slice, using another byte sliceas key
pub fn feistel_encrypt(plaintext: &[u8], key: &[u8], rounds: u32) -> Vec<u8> { 
    let mut _plaintext: &[u8] = plaintext.clone();
    let plaintext_length: usize = _plaintext.len();
    let (l, r) = _plaintext.split_at(plaintext_length / 2);
    let mut left: Vec<u8> = l.to_vec();
    let mut right: Vec<u8> = r.to_vec();

    let mut subkey: Vec<u8>;
    let mut tmp: Vec<u8>;
    let mut salt: u32;
    let mut updated_left: Vec<u8>;
    let mut updated_right: Vec<u8>;

    for i in 0..rounds {
        // 1. Create round key
        salt = key.iter().fold(0, |x, b| x+b.count_ones()) + i;
        subkey = key.iter().map(|x| x.rotate_left(salt)).collect();

        // L[i+1] = R[i]   Right side just moves to left side
        updated_left = right.clone().to_vec();

        // R[i+1] = L[i] ⊕ F(R[i], k[i])  Left side gets xored
        updated_right = Vec::new();
        tmp = round_fn(&right, &subkey);


        // 2. Xor. if else handles unbalanced Feistel where len(Right) != len(Left)
        if left.len() <= tmp.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ tmp[i]);
            }
        } else if left.len() > tmp.len() {
            for i in 0..tmp.len() {
                updated_right.push(left[i] ^ tmp[i]);
            }
            updated_right.push(left[left.len() - 1]);
        }

        // 3. swap left and right for next round
        right = updated_right;
        left = updated_left;
    }
    right.append(&mut left);
    right
}


pub fn feistel_decrypt(ciphertext: &[u8], key: &[u8], rounds: u32) -> Vec<u8> {
    let mut _ciphertext: &[u8] = ciphertext.clone();
    let ciphertext_length: usize = _ciphertext.len();
    let split_index;
    // Encryption gives us ciphertext of R + L for even amount of rounds
    // ensure we split at the proper index if ciphertext has odd length
    if (rounds % 2 == 0) && (ciphertext_length % 2 == 1) {
        split_index = (ciphertext_length / 2) + 1;
    } else {
        split_index = ciphertext_length / 2;
    }
    let (l, r) = _ciphertext.split_at(split_index);
    let mut left: Vec<u8> = l.to_vec();
    let mut right: Vec<u8> = r.to_vec();

    let mut subkey: Vec<u8>;
    let mut tmp: Vec<u8>;
    let mut salt: u32;
    let mut updated_left: Vec<u8>;
    let mut updated_right: Vec<u8>;

    for i in 0..rounds {
        salt = key.iter().fold(0, |x, b| x+b.count_ones()) + (rounds - i - 1);
        subkey = key.iter().map(|x| x.rotate_left(salt)).collect();

        // L[i+1] = R[i]
        updated_left = right.clone().to_vec();

        // R[i+1] = L[i] ⊕ F(R[i], k[i])
        updated_right = Vec::new();
        tmp = round_fn(&right, &subkey);

        if left.len() <= tmp.len() {
            for i in 0..left.len() {
                updated_right.push(left[i] ^ tmp[i]);
            }
        } else if left.len() > tmp.len() {
            for i in 0..tmp.len() {
                updated_right.push(left[i] ^ tmp[i]);
            }
            updated_right.push(left[left.len() - 1]);
        }
        assert_eq!(right, updated_left);
        right = updated_right;
        left = updated_left;
    }
    right.append(&mut left);
    right
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_hex::*;

    #[test]
    fn assert_functional_correctness() { // Assert that dec(enc(x))) == x and that enc(x) != x by testing many random inputs
        for i in 1..42 {
            let random_bytes: Vec<u8> = (0..(i*32 + (i % 1)) ).map(|_| { rand::random::<u8>() }).collect();
            let random_key: Vec<u8> = (0..(i*8 + (i % 1))).map(|_| { rand::random::<u8>() }).collect();
            let ciphertext = feistel_encrypt(&random_bytes, &random_key, i);
            let decrypted = feistel_decrypt(&ciphertext, &random_key, i);
            // Those prints show up if the test fails.
            println!("Random bytes: {}", simple_hex(&random_bytes));
            println!("Encrypted: {}", simple_hex(&ciphertext));
            println!("Decrypted: {}", simple_hex(&decrypted));
            assert_eq!(random_bytes, decrypted); // Assert Functional Correctness
            assert_ne!(random_bytes, ciphertext);
        }
    }
}