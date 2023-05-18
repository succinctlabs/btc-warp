use std::ops::Deref;

use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::blocks::block::Header;
use crate::circuits::btc::MultiHeaderTargetFlex;
use crate::circuits::l1::{compile_l1_circuit_flex, run_l1_circuit_flex, compile_and_run_ln_circuit_flex};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

/// Prover for all blocks up until predetermined checkpoint
/// Acts as a "gigaproof"
pub struct HistoryProver {
    pub header_target: MultiHeaderTargetFlex,
    pub last_circuit_data: CircuitData<F, C, D>,
    pub layer_num: usize,
    pub num_proofs: usize,
}

impl HistoryProver {
    /// Compile circuit for given layer
    pub fn new(layer_num: usize, pfs_per_layer: &Vec<usize>) -> Self {
        let (data, header_target) = compile_l1_circuit_flex(pfs_per_layer[0]).unwrap();
        let mut last_circuit_data = data;

        if layer_num > 1 {
            for i in 1..layer_num {
                let (_, data) = compile_and_run_ln_circuit_flex(
                    Vec::new(),
                    &last_circuit_data.verifier_only,
                    &last_circuit_data.common,
                    true,
                    pfs_per_layer[i]
                ).unwrap();
                last_circuit_data = data;
            }
        }

        Self {
            header_target,
            last_circuit_data,
            layer_num,
            num_proofs: pfs_per_layer[layer_num],            
        }
    }

    /// Prove headers for base layer 
    pub fn prove_headers(&self, headers: &[Header]) -> Vec<u8> {
        assert!(self.layer_num == 0, "Proving headers for non-base layer");

        let header_hexs = Header::to_hex_vec(headers.to_vec());
        self.prove_headers_string(&header_hexs)
    }

    pub fn prove_headers_string(&self, headers: &Vec<String>) -> Vec<u8> {
        assert!(self.layer_num == 0, "Proving headers for non-base layer");
        assert!(headers.len() == self.num_proofs, "Number of headers must match number of proofs");

        let headers_str = headers
            .iter()
            .map(|h| h.as_str())
            .collect::<Vec<_>>();

        let proof = run_l1_circuit_flex(
            &self.last_circuit_data,
            &self.header_target,
            &headers_str,
            self.num_proofs
        )
        .unwrap();

        proof.to_bytes().unwrap()
    }

    /// Prove headers for non-base layer
    pub fn prove_headers_layer(&self, proofs: Vec<Vec<u8>>) -> Vec<u8> {
        assert!(self.layer_num > 0, "Proving headers for non-leaf layer");
        assert!(proofs.len() == self.num_proofs, "Number of proofs must match number of proofs");

        let ps: Vec<ProofWithPublicInputs<F, C, D>> = proofs
            .iter()
            .map(|p_vec| {
                ProofWithPublicInputs::<F, C, D>::from_bytes(
                    p_vec.deref().to_vec(), 
                    &self.last_circuit_data.common
                ).unwrap()
            })
            .collect();
        let (proof, _) = compile_and_run_ln_circuit_flex(
            ps,
            &self.last_circuit_data.verifier_only,
            &self.last_circuit_data.common,
            false,
            self.num_proofs
        ).unwrap();

        proof.unwrap().to_bytes().unwrap()
    }

    pub fn headers_to_hex_slice(headers: &[Header]) -> Vec<String> {
        headers
            .iter()
            .map(|h| h.to_hex())
            .collect::<Vec<String>>()
    }
}
