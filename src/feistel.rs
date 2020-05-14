use std::io::prelude::*;

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

fn round_fn(right: &[u8], subkey: &[u8]) -> Vec<u8> {
    // PRF that takes two vectors and produces PRF output.
    let mut new_vec = right.to_vec();
    for (i, (right, key)) in right.iter().zip(subkey.iter()).enumerate() {
        new_vec[i] = *right ^ *key;
    }
    new_vec
}

// Feistel encryption function that encrypts a byte slice, using another byte sliceas key
pub fn feistel_encrypt(plaintext: &[u8], _key: &[u8], rounds: u32) -> Vec<u8> { 
    let mut _plaintext: &[u8] = plaintext.clone();
    let plaintext_length: usize = _plaintext.len();
    let (l, r) = _plaintext.split_at(plaintext_length / 2);
    let mut left: Vec<u8> = l.to_vec();
    let mut right: Vec<u8> = r.to_vec();

    let mut subkey: &[u8];
    let mut tmp: Vec<u8>;
    //let mut salty: &[u8];
    let mut updated_left: Vec<u8>;
    let mut updated_right: Vec<u8>;

    for _ in 0..rounds {
        // Subkey should be as unique as possible
        // salty = key.OnesInSlice() + x as u32;
        //salty = key.iter().fold(0, |x, b| x+b.count_ones()) + x;
        //subkey = key.wrapping_mul(salty);
        subkey = &[1, 2, 3, 4, 5, 6];

        // L[i+1] = R[i]
        updated_left = right.clone().to_vec();

        // R[i+1] = L[i] ⊕ F(R[i], k[i])
        updated_right = Vec::new();
        //updated_right = &[];
        tmp = round_fn(&right, subkey);

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
        right = updated_right;
        left = updated_left;
    }
    right.append(&mut left);
    right
}
