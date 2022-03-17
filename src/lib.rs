#![allow(dead_code)]
use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

pub struct MerkleTree {
    leaves: usize,
    hashes: Vec<Hash>
}

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

impl MerkleTree {
    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let mut ret: Vec<Hash> = input.iter().map(hash_data).collect();
        let mut children = ret.len();
        while children > 1 {
            let len = ret.len();
            for i in len - children .. len {
                ret.push(hash_concat(&ret[i], &ret[i + 1]))
            }
            children /= 2
        }
        Self { leaves: input.len(), hashes: ret }
    }

    pub fn root_hash(&self) -> Hash {
        self.hashes[self.leaves - 1].clone()
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        &Self::construct(input).root_hash() == root_hash
    }

}

fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use crate::{Data, MerkleTree};

    #[test]
    fn t_construct() {
        let d1 = [1, 2, 3, 4];
        let d2 = [8, 6, 7, 9];
        let d3 = [5, 2, 9, 4];
        let d4 = [3, 1, 2, 5];
        let d5 = [3, 2, 9, 7];
        let root_hash = MerkleTree::construct(&[Data::from(d1), Data::from(d2), Data::from(d3), Data::from(d4)]).root_hash();
        assert!(MerkleTree::verify(&[Data::from(d1), Data::from(d2), Data::from(d3), Data::from(d4)], &root_hash));
        assert!(!MerkleTree::verify(&[Data::from(d1), Data::from(d2), Data::from(d3), Data::from(d5)], &root_hash));
        assert!(!MerkleTree::verify(&[Data::from(d1), Data::from(d2), Data::from(d4), Data::from(d3)], &root_hash));
    }
}