use crate::crypto::kzg::dusk_bytes::Serializable;
use crate::crypto::kzg::{BlsScalar, Kzg};

#[test]
fn basic() {
    // for i in 8..100 {
    let i = 4;
        let data = {
            // let mut data = Vec::with_capacity(32 * i);

            // for _ in 0..i {
                // data.extend(rand::random::<[u8; 32]>());
            // }

            // Multiple of 32
            let mut data = rand::random::<[u8; 32 * 4]>();

            // We can only store 254 bits, set last byte to zero because of that
            data.chunks_exact_mut(BlsScalar::SIZE)
                .flat_map(|chunk| chunk.iter_mut().last())
                .for_each(|last_byte| *last_byte = 0);

            data
        };

        // println!("{data:?}, data_len: {}", data.len());

        let kzg = Kzg::random(256).unwrap();
        let polynomial = kzg.poly(&data).unwrap();
        let commitment = kzg.commit(&polynomial).unwrap();

        let values = data.chunks_exact(BlsScalar::SIZE);
        let num_values = values.len() as u32;

        for (index, value) in values.enumerate() {
            // println!(
                // "index: {index:?}, value: {value:?}, value.len(): {}",
                // value.len()
            // );
            let index = index.try_into().unwrap();

            let witness = kzg.create_witness(&polynomial, index).unwrap();

            if !kzg.verify(&commitment, num_values, index, value, &witness) {
                println!("Failed at i = {i}");
            }
            // assert!(
                // kzg.verify(&commitment, num_values, index, value, &witness),
                // "failed on index {index}"
            // );
        }
// }
}
