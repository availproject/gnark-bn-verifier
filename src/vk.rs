use super::{
    io::{unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point},
    types::{Groth16G1, Groth16G2},
};

#[derive(Clone, PartialEq)]
pub struct Groth16VKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
}

// attempt to deserialize some gnark formatted bytes into a vkey
impl<'a> TryFrom<&'a [u8]> for Groth16VKey {
    type Error = anyhow::Error;

    fn try_from(buffer: &'a [u8]) -> anyhow::Result<Self> {
        let g1_alpha = unchecked_compressed_x_to_g1_point(&buffer[..32])?;
        let g2_beta = unchecked_compressed_x_to_g2_point(&buffer[64..128])?;
        let g2_gamma = unchecked_compressed_x_to_g2_point(&buffer[128..192])?;
        let g2_delta = unchecked_compressed_x_to_g2_point(&buffer[224..288])?;

        let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
        let mut k = Vec::with_capacity(num_k as usize);
        let mut offset = 292;
        for _ in 0..num_k {
            let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
            k.push(point);
            offset += 32;
        }

        Ok(Self {
            g1: Groth16G1 { alpha: g1_alpha, k },
            g2: Groth16G2 {
                beta: -g2_beta,
                gamma: g2_gamma,
                delta: g2_delta,
            },
        })
    }
}
