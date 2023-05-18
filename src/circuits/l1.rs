use std::ops::AddAssign;

use anyhow::Result;
use hex::decode;
use num::BigUint;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

use crate::circuits::btc::{MultiHeaderTarget, MultiHeaderTargetFlex};
use crate::circuits::btc::{
    compute_exp_and_mantissa, compute_work, make_multi_header_circuit, 
    make_multi_header_circuit_flex, to_bits
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Compile a base layer circuit for verifying several headers together
pub fn compile_l1_circuit(num_headers: usize) -> Result<(CircuitData<F, C, D>, MultiHeaderTarget)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = make_multi_header_circuit(&mut builder, num_headers);

    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_start_hash[i].target);
        builder.connect(public_start_hash[i].target, targets.hashes[0][i].target);
    }

    let mut public_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_end_hash[i].target);
        builder.connect(
            public_end_hash[i].target,
            targets.hashes[num_headers - 1][i].target,
        );
    }

    let public_total_work = builder.add_virtual_biguint_target(8);
    println!("{:?}", targets.total_work.num_limbs());
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
        builder.connect(public_total_work.limbs[i].0, targets.total_work.limbs[i].0);
    }

    Ok((builder.build::<C>(), targets))
}

/// Execute a base layer circuit for verifying several headers to return a proof
pub fn run_l1_circuit(
    data: &CircuitData<F, C, D>,
    targets: &MultiHeaderTarget,
    headers: &[&str],
    num_headers: usize,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut total_work = BigUint::new(vec![0]);
    let mut pw = PartialWitness::<F>::new();

    for h in 0..num_headers {
        let header_bits = to_bits(decode(headers[h]).unwrap());
        for i in 0..80 * 8 {
            pw.set_bool_target(targets.headers[h * 80 * 8 + i], header_bits[i]);
        }

        let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
        let header_work = compute_work(exp, mantissa);
        total_work.add_assign(header_work);

        for i in 0..256 {
            if i < 256 - exp
                && mantissa as u128 & (1u128 << (255u128 - exp as u128 - i as u128)) != 0
            {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], true);
            } else {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], false);
            }
        }
    }

    let proof = data.prove(pw).unwrap();

    match data.verify(proof.clone()) {
        Ok(_) => {}
        Err(e) => {
            panic!("Proof did not verify, error: {e:#?}");
        }
    }

    Ok(proof)
}

pub fn compile_and_run_ln_circuit(
    inner_proofs: Vec<ProofWithPublicInputs<F, C, 2>>,
    inner_vd: &VerifierOnlyCircuitData<C, D>,
    inner_cd: &CommonCircuitData<F, D>,
    num_proofs: usize,
    only_compile: bool,
) -> Result<(Option<ProofWithPublicInputs<F, C, D>>, CircuitData<F, C, D>)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::<F>::new();

    let zero = builder.zero();

    let mut pts = Vec::new();
    let mut inner_datas = Vec::new();

    // Connect first hash and check last hash in chain
    // If not a valid chain, the last hash will be mismatched
    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_start_hash[i].target);
    }
    let mut public_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_end_hash[i].target);
    }

    // Connect total work verification
    let public_total_work = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
    }
    let mut work_accumulator = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.connect(work_accumulator.limbs[i].0, zero);
    }

    for i in 0..num_proofs {
        let pt: ProofWithPublicInputsTarget<D> = builder.add_virtual_proof_with_pis::<C>(inner_cd);
        let inner_data = VerifierCircuitTarget {
            circuit_digest: builder.add_virtual_hash(),
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
        };

        // We only set the witness if are not only compiling
        if !only_compile {
            pw.set_proof_with_pis_target(&pt, &inner_proofs[i]);
            pw.set_verifier_data_target(&inner_data, inner_vd);
        }

        let current_work = builder.add_virtual_biguint_target(8);
        for i in 0..8 {
            builder.connect(pt.public_inputs[512 + i], current_work.limbs[i].0);
        }
        work_accumulator = builder.add_biguint(&work_accumulator, &current_work);

        // Connect work verification targets
        // On last iteration, must be connected to "out" work wire
        if i == 0 {
            for i in 0..256 {
                // tmp = public_start_hash[i].target if consistent else 0
                builder.connect(public_start_hash[i].target, pt.public_inputs[i]);
            }
        }
        if i == num_proofs - 1 {
            for i in 0..256 {
                builder.connect(public_end_hash[i].target, pt.public_inputs[256 + i]);
            }
            for i in 0..8 {
                builder.connect(work_accumulator.limbs[i].0, public_total_work.limbs[i].0);
            }
        }

        pts.push(pt);
        inner_datas.push(inner_data);
    }

    // Chain proofs together
    for i in 0..(num_proofs - 1) {
        let pt1: &ProofWithPublicInputsTarget<D> = &pts[i];
        let pt2: &ProofWithPublicInputsTarget<D> = &pts[i + 1];
        for j in 0..256 {
            builder.connect(pt1.public_inputs[256 + j], pt2.public_inputs[j]);
        }
    }

    // Verify proofs
    pts.into_iter().enumerate().for_each(|(i, pt)| {
        builder.verify_proof::<C>(pt, &inner_datas[i], inner_cd);
    });

    let data = builder.build::<C>();
    if !only_compile {
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone())?;
        Ok((Some(proof), data))
    } else {
        Ok((None, data))
    }
}

/// Compile a base layer circuit for verifying several headers together
pub fn compile_l1_circuit_flex(
    num_headers: usize,
) -> Result<(CircuitData<F, C, D>, MultiHeaderTargetFlex)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = make_multi_header_circuit_flex(&mut builder, num_headers);
    let _zero = builder.zero();

    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_start_hash[i].target);
        builder.connect(public_start_hash[i].target, targets.hashes[0][i].target);
    }

    let mut public_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_end_hash[i].target);
        builder.connect(
            public_end_hash[i].target,
            targets.hashes[num_headers - 1][i].target,
        );
    }

    let public_total_work = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
        builder.connect(public_total_work.limbs[i].0, targets.total_work.limbs[i].0);
    }

    Ok((builder.build::<C>(), targets))
}

/// Execute a base layer circuit for verifying several headers to return a proof
pub fn run_l1_circuit_flex(
    data: &CircuitData<F, C, D>,
    targets: &MultiHeaderTargetFlex,
    headers: &[&str],
    num_headers: usize,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut total_work = BigUint::new(vec![0]);
    let mut pw = PartialWitness::<F>::new();

    for h in 0..num_headers {
        let header_bits = to_bits(decode(headers[h]).unwrap());
        for i in 0..80 * 8 {
            pw.set_bool_target(targets.headers[h * 80 * 8 + i], header_bits[i]);
        }

        let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
        let header_work = compute_work(exp, mantissa);
        total_work.add_assign(header_work);

        for i in 0..256 {
            if i < 256 - exp
                && mantissa as u128 & (1u128 << (255u128 - exp as u128 - i as u128)) != 0
            {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], true);
            } else {
                pw.set_bool_target(targets.multi_threshold_bits[h * 256 + i as usize], false);
            }
        }
    }

    let proof = data.prove(pw).unwrap();

    match data.verify(proof.clone()) {
        Ok(_) => {}
        Err(e) => {
            panic!("Proof did not verify, error: {e:#?}");
        }
    }

    Ok(proof)
}

/// Create layer n circuit for proof tree
/// Handles logic of "forwarding" left-most proof to next level if >=1 proofs do not exist
pub fn compile_and_run_ln_circuit_flex(
    inner_proofs: Vec<ProofWithPublicInputs<F, C, 2>>,
    inner_vd: &VerifierOnlyCircuitData<C, D>,
    inner_cd: &CommonCircuitData<F, D>,
    only_compile: bool,
    num_proofs: usize,
) -> Result<(Option<ProofWithPublicInputs<F, C, D>>, CircuitData<F, C, D>)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let mut pw = PartialWitness::<F>::new();
    let _zero = builder.zero();

    let mut pts = Vec::new();
    let mut inner_datas = Vec::new();

    // Connect first hash and check last hash in chain
    // If not a valid chain, the last hash will be mismatched
    let mut public_start_hash = Vec::new();
    for i in 0..256 {
        public_start_hash.push(builder.add_virtual_bool_target_safe());
        builder.register_public_input(public_start_hash[i].target);
    }
    let mut public_end_hash = Vec::new();
    let mut tmp_end_hash = Vec::new();
    for i in 0..256 {
        public_end_hash.push(builder.add_virtual_bool_target_safe());
        tmp_end_hash.push(builder._true());
        builder.register_public_input(public_end_hash[i].target);
    }

    // Connect total work verification
    let public_total_work = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.register_public_input(public_total_work.limbs[i].0);
    }
    let mut work_accumulator = builder.add_virtual_biguint_target(8);
    for i in 0..8 {
        builder.connect(work_accumulator.limbs[i].0, _zero);
    }

    // Compute if proofs are consistent
    for i in 0..num_proofs {
        let pt: ProofWithPublicInputsTarget<D> = builder.add_virtual_proof_with_pis::<C>(inner_cd);
        let inner_data = VerifierCircuitTarget {
            circuit_digest: builder.add_virtual_hash(),
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
        };
        // We only set the witness if are not only compiling
        if !only_compile {
            pw.set_proof_with_pis_target(&pt, &inner_proofs[i]);
            pw.set_verifier_data_target(&inner_data, inner_vd);
        }

        pts.push(pt);
        inner_datas.push(inner_data);
    }

    let mut so_far = builder.one();
    let f = builder.zero();
    for i in 1..num_proofs {
        let pt1: &ProofWithPublicInputsTarget<D> = &pts[i - 1];
        let pt2: &ProofWithPublicInputsTarget<D> = &pts[i];

        let bool_so_far = builder.add_virtual_bool_target_safe();

        // For first iteration, know that we need to make this connection
        if i == 1 {
            for j in 0..256 {
                builder.connect(public_start_hash[j].target, pt1.public_inputs[j]);
                tmp_end_hash[j].target = pt1.public_inputs[256 + j];
            }
        }

        // Check consistency
        for j in 0..256 {
            let eq = builder.is_equal(pt2.public_inputs[j], pt1.public_inputs[256 + j]);
            so_far = builder.select(eq, so_far, f);
        }
        builder.connect(bool_so_far.target, so_far);

        // Accumulate work if consistency, else noop
        let mut limbs = Vec::new();
        for j in 0..8 {
            let bool_so_far = BoolTarget::new_unsafe(so_far);
            let limb = builder.select(bool_so_far, pt1.public_inputs[512 + j], _zero);
            limbs.push(U32Target(limb));
        }
        let curr_work = BigUintTarget { limbs };
        work_accumulator = builder.add_biguint(&work_accumulator, &curr_work);

        // If consistent, update to new proof's end hash, else noop
        // Also connect proof i's start hash to proof i-1's end hash
        for j in 0..256 {
            tmp_end_hash[j].target = builder.select(
                bool_so_far,
                pt2.public_inputs[256 + j],
                tmp_end_hash[j].target,
            );

            let connect_bit = builder.select(
                bool_so_far,
                pt2.public_inputs[j],
                pt1.public_inputs[256 + j],
            );
            builder.connect(pt1.public_inputs[256 + j], connect_bit);
        }

        // For last iteration, know that we need to connect work accumulator to this connection
        if i == num_proofs - 1 {
            for j in 0..8 {
                builder.connect(work_accumulator.limbs[j].0, public_total_work.limbs[j].0);
            }
            for j in 0..256 {
                builder.connect(public_end_hash[j].target, tmp_end_hash[j].target);
            }
        }
    }

    pts.into_iter().enumerate().for_each(|(i, pt)| {
        builder.verify_proof::<C>(pt, &inner_datas[i], inner_cd);
    });

    let data = builder.build::<C>();
    if !only_compile {
        let proof = data.prove(pw).unwrap();
        data.verify(proof.clone())?;
        Ok((Some(proof), data))
    } else {
        Ok((None, data))
    }
}

#[cfg(test)]
mod tests {
    use crate::circuits::l1::{
        compile_and_run_ln_circuit, compile_and_run_ln_circuit_flex, compile_l1_circuit, 
        compile_l1_circuit_flex, run_l1_circuit, run_l1_circuit_flex,
    };
    use anyhow::Result;
    use plonky2::plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs};
    use plonky2_field::{goldilocks_field::GoldilocksField, types::PrimeField64};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_compile_and_run_l1_circuit() -> Result<()> {
        let num_headers = 2;
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
        ];

        let compile_now = std::time::Instant::now();
        let (circuit_data, targets) = compile_l1_circuit(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();
        let proof = run_l1_circuit(&circuit_data, &targets, &headers, num_headers).unwrap();
        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation took {proof_elapsed:?}ms");

        circuit_data.verify(proof)
    }

    #[test]
    fn test_compile_and_run_ln_circuit() -> Result<()> {
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        ];

        // Extract headers in a "state transition" way
        let headers_1 = &[headers[0], headers[1]];
        let headers_2 = &[headers[1], headers[2]];
        let headers_3 = &[headers[2], headers[3]];
        let headers_4 = &[headers[3], headers[4]];

        let compile_now = std::time::Instant::now();
        let (data, targets) = compile_l1_circuit(2).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();

        let proof1 = run_l1_circuit(&data, &targets, headers_1, 2).unwrap();
        println!("stage 0, batch 1");

        let proof2 = run_l1_circuit(&data, &targets, headers_2, 2).unwrap();
        println!("stage 0, batch 2");

        let proof3 = run_l1_circuit(&data, &targets, headers_3, 2).unwrap();
        println!("stage 0, batch 3");

        let proof4 = run_l1_circuit(&data, &targets, headers_4, 2).unwrap();
        println!("stage 0, batch 4");

        let proof_merge_1 = compile_and_run_ln_circuit(
            vec![proof1, proof2],
            &data.verifier_only,
            &data.common,
            2,
            false,
        )
        .unwrap();
        println!("stage 1, batch 0");

        let proof_merge_2 = compile_and_run_ln_circuit(
            vec![proof3, proof4],
            &data.verifier_only,
            &data.common,
            2,
            false,
        )
        .unwrap();
        println!("stage 1, batch 1");

        let _final_proof = compile_and_run_ln_circuit(
            vec![proof_merge_1.0.unwrap(), proof_merge_2.0.unwrap()],
            &proof_merge_1.1.verifier_only,
            &proof_merge_1.1.common,
            2,
            false,
        )
        .unwrap();
        println!("stage 2, batch 0");

        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation and layering took {proof_elapsed:?}ms");

        Ok(())
    }

    #[test]
    fn test_proof_serialization() -> Result<()> {
        let num_headers = 2;
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
        ];

        // Extract headers in a "state transition" way
        let headers_1 = &[headers[0], headers[1]];
        let headers_2 = &[headers[1], headers[2]];

        let compile_now = std::time::Instant::now();
        let (data, targets) = compile_l1_circuit(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();

        // Generate proofs
        let proof1 = run_l1_circuit(&data, &targets, headers_1, 2).unwrap();
        println!("stage 0, batch 1");

        let proof2 = run_l1_circuit(&data, &targets, headers_2, 2).unwrap();
        println!("stage 0, batch 2");

        // Attempt serialization
        let p1_bytes = proof1.to_bytes().unwrap();
        let p2_bytes = proof2.to_bytes().unwrap();
        // Attempt deserialization
        let p1_from_bytes =
            ProofWithPublicInputs::<F, C, D>::from_bytes(p1_bytes, &data.common).unwrap();
        let p2_from_bytes =
            ProofWithPublicInputs::<F, C, D>::from_bytes(p2_bytes, &data.common).unwrap();

        // Attempt to merge deserialized proofs
        let _proof_merge = compile_and_run_ln_circuit(
            vec![p1_from_bytes, p2_from_bytes],
            &data.verifier_only,
            &data.common,
            2,
            false,
        )
        .unwrap();

        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation and merging took {proof_elapsed:?}ms");

        Ok(())
    }

    #[test]
    fn test_l1_circuit_flex_simple() -> Result<()> {
        let num_headers = 10;
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53"
        ];

        let compile_now = std::time::Instant::now();
        let (circuit_data, targets) = compile_l1_circuit_flex(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();
        let proof = run_l1_circuit_flex(&circuit_data, &targets, &headers, num_headers).unwrap();
        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation took {proof_elapsed:?}ms");
        println!("Proof public inputs: {:?}", proof.public_inputs);

        circuit_data.verify(proof)
    }

    #[test]
    fn test_l1_circuit_flex_hard() -> Result<()> {
        let num_headers = 10;
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
            // valid chain broken here
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53"
        ];

        let compile_now = std::time::Instant::now();
        let (circuit_data, targets) = compile_l1_circuit_flex(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();
        let proof = run_l1_circuit_flex(&circuit_data, &targets, &headers, num_headers).unwrap();
        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation took {proof_elapsed:?}ms");
        println!("Proof public inputs: {:?}", proof.public_inputs);

        circuit_data.verify(proof)
    }

    #[test]
    fn test_ln_circuit_flex_simple() -> Result<()> {
        // Simple test: for a 4 state transition proof merging tree, how to handle the
        // "upgrading" of the valid proofs to the next level with a valid circuit
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
        ];
        let num_headers = 2usize;

        // Extract headers in a "state transition" way
        let headers_1 = &[headers[0], headers[1]];
        let headers_2 = &[headers[1], headers[2]];
        let headers_3 = &[headers[2], headers[3]];
        let headers_4 = &[headers[3], headers[4]];

        // Compile base layer circuit
        let compile_now = std::time::Instant::now();
        let (l0_data, targets) = compile_l1_circuit_flex(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();

        let proof1 = run_l1_circuit_flex(&l0_data, &targets, headers_1, num_headers).unwrap();
        println!("stage 0, batch 1");

        let proof2 = run_l1_circuit_flex(&l0_data, &targets, headers_2, num_headers).unwrap();
        println!("stage 0, batch 2");

        let proof3 = run_l1_circuit_flex(&l0_data, &targets, headers_3, num_headers).unwrap();
        println!("stage 0, batch 3");

        let proof4 = run_l1_circuit_flex(&l0_data, &targets, headers_4, num_headers).unwrap();
        println!("stage 0, batch 4");

        let proof_merge_1 = compile_and_run_ln_circuit_flex(
            vec![proof1, proof2],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            num_headers,
        )
        .unwrap();
        println!("stage 1, batch 1");

        let proof_merge_2 = compile_and_run_ln_circuit_flex(
            vec![proof3, proof4],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            num_headers,
        )
        .unwrap();
        println!("stage 1, batch 2");

        let (final_proof, data) = compile_and_run_ln_circuit_flex(
            vec![proof_merge_1.0.unwrap(), proof_merge_2.0.unwrap()],
            &proof_merge_1.1.verifier_only,
            &proof_merge_1.1.common,
            false,
            num_headers,
        )
        .unwrap();
        println!("stage 2, batch 0");

        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation and layering took {proof_elapsed:?}ms");

        let expected_end_hash = "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485";
        let end_hash_field = final_proof.clone().unwrap().public_inputs[256..512].to_vec();
        let mut end_hash_bits = Vec::new();
        for i in 0..end_hash_field.len() {
            end_hash_bits.push(end_hash_field[end_hash_field.len() - i - 1].to_canonical_u64() != 0);
        }
        let end_hash = bits_to_hex(&end_hash_bits).to_lowercase();
        assert_eq!(end_hash, expected_end_hash);

        println!("Verifying final proof...");
        data.verify(final_proof.unwrap())?;
        println!("Final proof verified!");

        Ok(())
    }

    #[test]
    fn test_ln_circuit_flex_medium() -> Result<()> {
        // Medium test: for a 16 state transition proof merging tree, how to handle the
        // "upgrading" of the valid proofs to the next level with a valid circuit
        // Invalid transition from 9->9 in the end
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299", 
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61", 
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d", 
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9", 
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477", 
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97", 
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86", 
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666", 
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53", 
            "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565", 
            "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8", 
            "010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c", 
            "010000005e2b8043bd9f8db558c284e00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86", 
            "0100000089304d4ba5542a22fb616d1ca019e94222ee45c1ad95a83120de515c00000000560164b8bad7675061aa0f43ced718884bdd8528cae07f24c58bb69592d8afe185d36649ffff001d29cbad24", 
            "01000000378a6f6593e2f0251132d96616e837eb6999bca963f6675a0c7af180000000000d080260d107d269ccba9247cfc64c952f1d13514b49e9f1230b3a197a8b7450fa276849ffff001d38d8fb98",
        ];
        let num_headers = 4usize;

        // Extract headers in a "state transition" way
        let headers_1 = &[headers[0], headers[1], headers[2], headers[3]];
        let headers_2 = &[headers[3], headers[4], headers[5], headers[6]];
        let headers_3 = &[headers[6], headers[7], headers[8], headers[9]];
        let headers_4 = &[headers[9], headers[9], headers[11], headers[12]];

        // Compile base layer circuit
        let compile_now = std::time::Instant::now();
        let (l0_data, targets) = compile_l1_circuit_flex(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();

        let proof1 = run_l1_circuit_flex(&l0_data, &targets, headers_1, num_headers).unwrap();
        println!("stage 0, batch 1");

        let proof2 = run_l1_circuit_flex(&l0_data, &targets, headers_2, num_headers).unwrap();
        println!("stage 0, batch 2");

        let proof3 = run_l1_circuit_flex(&l0_data, &targets, headers_3, num_headers).unwrap();
        println!("stage 0, batch 3");

        // Dummy proof!
        let proof4 = run_l1_circuit_flex(&l0_data, &targets, headers_4, num_headers).unwrap();
        println!("stage 0, batch 4");

        let proof_merge_1 = compile_and_run_ln_circuit_flex(
            vec![proof1, proof2],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            2,
        )
        .unwrap();
        println!("stage 1, batch 1");

        let proof_merge_2 = compile_and_run_ln_circuit_flex(
            vec![proof3, proof4],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            2,
        )
        .unwrap();
        println!("stage 1, batch 2");

        let (final_proof, data) = compile_and_run_ln_circuit_flex(
            vec![proof_merge_1.0.unwrap(), proof_merge_2.0.unwrap()],
            &proof_merge_1.1.verifier_only,
            &proof_merge_1.1.common,
            false,
            2,
        )
        .unwrap();
        println!("stage 2, batch 0");

        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation and layering took {proof_elapsed:?}ms");

        let expected_end_hash = "000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805";
        let end_hash_field = final_proof.clone().unwrap().public_inputs[256..512].to_vec();
        let mut end_hash_bits = Vec::new();
        for i in 0..end_hash_field.len() {
            end_hash_bits.push(end_hash_field[end_hash_field.len() - i - 1].to_canonical_u64() != 0);
        }
        let end_hash = bits_to_hex(&end_hash_bits).to_lowercase();
        assert_eq!(end_hash, expected_end_hash);

        println!("Verifying final proof...");
        data.verify(final_proof.unwrap())?;
        println!("Final proof verified!");

        Ok(())
    }

    #[test]
    fn test_ln_circuit_flex_big() -> Result<()> {
        // Big test: for a 64 state transition proof merging tree, how to handle the
        // "upgrading" of the valid proofs to the next level with a valid circuit
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299", 
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61", 
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d", 
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9", 
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477", 
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97", 
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86", 
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666", 
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53", 
            "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565", 
            "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8", 
            "010000007330d7adf261c69891e6ab08367d957e74d4044bc5d9cd06d656be9700000000b8c8754fabb0ffeb04ca263a1368c39c059ca0d4af3151b876f27e197ebb963bc8d06649ffff001d3f596a0c", 
            "010000005e2b8043bd9f8db558c284e00ea24f78879736f4acd110258e48c2270000000071b22998921efddf90c75ac3151cacee8f8084d3e9cb64332427ec04c7d562994cd16649ffff001d37d1ae86", 
            "0100000089304d4ba5542a22fb616d1ca019e94222ee45c1ad95a83120de515c00000000560164b8bad7675061aa0f43ced718884bdd8528cae07f24c58bb69592d8afe185d36649ffff001d29cbad24", 
            "01000000378a6f6593e2f0251132d96616e837eb6999bca963f6675a0c7af180000000000d080260d107d269ccba9247cfc64c952f1d13514b49e9f1230b3a197a8b7450fa276849ffff001d38d8fb98", 
            "010000007384231257343f2fa3c55ee69ea9e676a709a06dcfd2f73e8c2c32b300000000442ee91b2b999fb15d61f6a88ecf2988e9c8ed48f002476128e670d3dac19fe706286849ffff001d049e12d6", 
            "01000000f5c46c41c30df6aaff3ae9f74da83e4b1cffdec89c009b39bb254a17000000005d6291c35a88fd9a3aef5843124400936fbf2c9166314addcaf5678e55b7e0a30f2c6849ffff001d07608493", 
            "0100000009f8fd6ba6f0b6d5c207e8fcbcf50f46876a5deffbac4701d7d0f13f0000000023ca63b851cadfd7099ae68eb22147d09394adb72a78e86b69c42deb6df225f92e2e6849ffff001d323741f2", 
            "01000000161126f0d39ec082e51bbd29a1dfb40b416b445ac8e493f88ce993860000000030e2a3e32abf1663a854efbef1b233c67c8cdcef5656fe3b4f28e52112469e9bae306849ffff001d16d1b42d", 
            "010000006f187fddd5e28aa1b4065daa5d9eae0c487094fb20cf97ca02b81c84000000005b7b25b51797f83192f9fd2c3871bfb27570a7d6b56d3a50760613d1a2fc1aeeab346849ffff001d36d95071", 
            "01000000d7c834e8ea05e2c2fddf4d82faf4c3e921027fa190f1b8372a7aa96700000000b41092b870cc096070ff3212c207c0881e3a2abafc1b92507941b4ef705917e0d9366849ffff001d2bd021d6", 
            "010000004f29f31e6dac13710ae72d54278b5c97ff6c1646e95b27d14263016f000000004349d6a4e94f05a736ac830754e76dfdf7f140c331f316d1a278517e1daf2e9e6b3a6849ffff001d28140f62", 
            "010000003b5e5b888c8c3da0f1d6c3969e63a7a9c1215a3360c8107a428db598000000008c4cc1b42c9dab1973890ecdfdee032079ed39892ad53a6546844d237634cfe1fb3a6849ffff001d255ab455", 
            "0100000082219cebbdc9bcb715efee535c13a44447e99dfaff6d552e9839d30c000000003e75f63c634ed5fb3d8e21de5fe143cfa63c8018fce0fa26cbc628378b9bc343953d6849ffff001d27ba00b1", 
            "010000005f411e0d7783fc274b4fea8597209d31d4a511e887a489cebb1f05fc00000000be2123ad48038313b8b726a51cb080bb5a8b81c4166401493b017d2d33520f9b063f6849ffff001d2337f131", 
            "010000002620766fa24558ad47e3a9623cd17ff4623668768dbea19ed5a1358e00000000dc1490b5ba227b1adbb2513f74e0252e8fe68b6c7de74c1a22adb63b14e8c16712466849ffff001d344eb75c", 
            "010000009810f0fa1817a4d2d371a069addaafab2ca99887abcc5bd2528e434100000000654f005a6e4b4b57b42343fb0e47f32079b4ebfe643c2ea4ea20e46c3af00c238d466849ffff001d364c8cb3", 
            "0100000081203520416c370fde3d6d46e82ed4332b5035bfba848ff97207357100000000bdaed84e0cbab735880d4763a1eb2df1ecd59dc261f3446db37bed5b6ccb99f331bf6849ffff001d2e5bd48e", 
            "010000004409709aff1b155be4f7a9ccef6121345050be74b4bad1d330940dbb00000000ec77d34cb2f84f3447c37ec1b4476e044e88478378998bd55d031f58f4e261c35fbf6849ffff001d32cb39a0", 
            "01000000cb9ba5a45252b335fe47a099c8935d01ff8eef2e598c2051631b7ac50000000031534f7571b5ea98c1318eed04937d6ff16582ba72c53552581c40828b6ce2f5cac16849ffff001d080315e8", 
            "01000000db643f0756bb4f6b25ce4a475b533d9ef75cd536e72df664fb9c91bc00000000cb527bd29495c02c9d6515de91ef264df333447e48ef730f3b66ffa8db3eb38630c46849ffff001d155dbb2a", 
            "01000000c4d369b723c2cf9be33cf00deb1dbfea0c8ccd12c415f29434ff009700000000c9c0fd0ae7b7973c42fc9e3dddc967b6e309570b720ff15414c08365f005992be3c56849ffff001d08e1c00d", 
            "01000000e3f6664d5af37062b934f983ed1033e2011b42c9b04735276c7ccbe5000000001012aaab3e3bffd34055aaa157bf78792d5c18f085635eda7046d89c08a0eabde3c86849ffff001d228c2240", 
            "01000000627985c0fc1a71e052a5af9420c9b99845432ae099f27a3dea7370a80000000074549b3151d6dd4ce77419d01710921b3211ed3280bf2e3af2c1f1a820063b2272ca6849ffff001d2243c024", 
            "010000008f31b4c405cfc212fa4e62840dc8d0c529ed53328bb1426c3bb23fa700000000e0af3bba9e962ce288d9e232d28a1ba9c85bd1e298890738a65b93ed97192b85a1cd6849ffff001d14cadde7", 
            "010000009b2d32c7828a80644b92b773357b557462a1470d4216e8b465a472b5000000005a4d7d92cd839cdb7dc448902438e4a4885721487de33900b34558bd6f255dd01dd06849ffff001d2ec3842f", 
            "01000000de44324d0f70a14985385f4399844b17925ca24e90b425f543d624f8000000007d282068b770b35b587a9fb4356491d5854bba3b60d7c1a129d37ed6b54e346dead36849ffff001d013eca85", 
            "01000000866f0cc679170b6a99e8b93e58dc276cf64f0379112d128e126dd9dd00000000689a44cb1c69d8aade6a37d48322b3e97099c25e4bcb228a9dd2739febda90e6c0d66849ffff001d0003e8ea", 
            "01000000ddd64fea2fd6e3b10b1456f2ad2a870ff5ff8ed524304d928eee197c000000006bcae7125656cc0d6b3dc563ab3e98d5496dcbd89785095138b143a48bc18414d7d66849ffff001d28000260", 
            "0100000012ad62326d4d1d7d32d2f169a1a816984f6298fdb5ccc3f606d5655600000000201e1ad44f0ae957771d2e60fa252594e7fcc75a51db4cdfb5fbaeb38612390490d96849ffff001d06216771", 
            "01000000aa698b967619b95c9181ebd256700651aaa1255fe503f59b391ff0b2000000005a8da000e1a2258630dd6f0286ddc24b7b0ef897f3447138c9a3ccb8b36cfa9e47dc6849ffff001d07e8fbd1", 
            "010000008b52bbd72c2f49569059f559c1b1794de5192e4f7d6d2b03c7482bad0000000083e4f8a9d502ed0c419075c1abb5d56f878a2e9079e5612bfb76a2dc37d9c42741dd6849ffff001d2b909dd6", 
            "01000000f528fac1bcb685d0cd6c792320af0300a5ce15d687c7149548904e31000000004e8985a786d864f21e9cbb7cbdf4bc9265fe681b7a0893ac55a8e919ce035c2f85de6849ffff001d385ccb7c", 
            "0100000050e593d3b22034cfc9884df842e85d398b5c3cfd77b1aa2a86f221ac000000005fafe0e1824bb9995f12eeb4183eaa1fde889f4590191cd63a92a61a1eee9a43f9e16849ffff001d30339e19", 
            "01000000f8000cd0261cdcd7215149ff2f0090c93b0857f0f720d0e8cdee782900000000d9a6665d16cf43ec412e38aef57098c9b5ff613bfefc1ceaa1781e5f087897f6bce46849ffff001d21be2da5", 
            "01000000bb36b800114609bfdd0019c02a411702d019a837402f1d466e00899100000000fa2fb24edda69806924fe1ef06bd073264d8b32f55eeaacab45a156563d0d4dd91e76849ffff001d0195ec60", 
            "010000008ec0e98eaa3378c803880364eb6d696974772bf8d9a9e3a229f4d50200000000f6ef70bb4846dffdefb6daa75c87d7021f01d7ed0590fb9d040993609c9c7bd1d8eb6849ffff001d20e842b0", 
            "01000000817ac590d6cd50e70cf710266e33382088e111e774a86af831455c1a000000008a15f1ddaef05f8acb0db86b2f4534f68d417f05de65a64073c3d0b7e0eded32d4ec6849ffff001d1b6910e0", 
            "01000000896e8271cf721a5db7b1dbae43b40eac2a7b0247870b06f47802968800000000595badffff2bb1453255880ba0f33d7be62a2f55b6f266bc26869d2715974c196aef6849ffff001d2c5bb2b3", 
            "01000000008de6ae7a37b4f26a763f4d65c5bc7feb1ad9e3ce0fff4190c067f0000000000913281db730c5cff987146330508c88cc3e642d1b9f5154854764fd547e0a54eaf26849ffff001d2e4a4c3d", 
            "0100000033aa0fa26441ead7005df4b0ad2e61405e80cb805e3c657f194df3260000000021184d335529aae22259315be42915b0360deeae97ec428a654014a3d2899ca00ff66849ffff001d0948811f", 
            "01000000632dfba41dda58eec7b6db8f75b25a69a38829915c82e6d1001e511c000000004f08f5265053c96c4eb51eac4ad3f5c668323f4b630af32a66915eeee678f9b36bf96849ffff001d399f07f1", 
            "01000000b5969273528cd8cee5b13a095762d731d9c5e30a21b4713ef255c6d600000000f54667bee8511d31bb173bcc6f15b0bf3dc42788a813439bfea9065f90586f3ca6fc6849ffff001d2c950522", 
            "0100000005ba6ff20c063f7f23b49c53d7004941241eb5347616f406333fdefc00000000b57076c0e5f498a6f06ef26c72e224cd7e25784ed6cd569e570988d5e59bdcd36afd6849ffff001d2edcf3b7", 
            "010000005b74dda1cc03078d30fe49722218667eb31524f22c59687ac30fe04e00000000ede29e76449491b0e2b766dc213c0e15bd7ab6eae48a7cb399c22a48621c5219cd016949ffff001d1b8557c3", 
            "0100000083527a686e27387544d284257d9238c5fe3d50fc9e6ceb5b8d8b4346000000000201df27519bd574817d5449758f744e42d648415d1370b17ac6448b6ccc9cfe20036949ffff001d05727a3e", 
            "01000000c0d1e5e651f40fd9b0a4fe024b79f15fa65f1d85bbf265582ccf93f0000000002837870b786929d9e30d651dcda7c3006a04b79d292261031a4235328b0f0fbc5c066949ffff001d1c00dd1d", 
            "01000000917354007e87c5ea0a1bea34d5275718a40d082bdd28717d7075f34f00000000e43721163a2bdbc80493a9e0b65d20b1ce63ec4c5ffadc39ea01e13d4e053596d4096949ffff001d1e2f1812", 
            "01000000f12ee37c151ee80a22be4f6ff155646addc588cf604e3cf354dfb4750000000095ca77f0c5dfd190be1eab32399d93555666cdadb8f44eb0636a608414b10d3c400b6949ffff001d160ab450", 
            "010000004aa5ae0b1842e2daa39a019e1a6cfad2306aae707b035f3ee571710f000000002d00540fb7aa5cf6fefc567912eeef891a19ac2f9fc055eafd229b1a73e1a182470f6949ffff001d02956322", 
            "01000000df2c4d42797dd61991b8df3033716f364b33f87a7cbd3494b8587ac400000000e1fe31bd4e94cd3a004849125ac5951703d34b33f3a90ca1ddc67ae4f8ed6eae2d116949ffff001d37466753", 
            "01000000c49052b367c9cfc10792aac007acdf986aa1e60fdbb87193cbd6732900000000eea3f31766c62e47ca1e9ccd303e37404887a570375079fa030b3e036ce71c7038146949ffff001d0552ee6b", 
            "010000002aa08c1efce70618d7370e0383a0b5801cafc5ecdc8108e34d93fe42000000004f0c28db6791823456c979edc21f8e9615a037c410299a745f2e7af03cf33107c8166949ffff001d22e2cd27",
            "010000005002c9b34042ac70ac8e36b1840672d69cb0ba6ada5effb6477de4aa00000000743a0389e4d8c9f60ad41025b797fd25e228123c4b54b5df20ed02ca97781df03c1b6949ffff001d21537e7a"
        ];
        let num_headers = 9usize;

        // Extract headers in a "state transition" way
        let headers_1 = &[
            headers[0], headers[1], headers[2], headers[3], 
            headers[4], headers[5], headers[6], headers[7],
            headers[8]
        ];
        let headers_2 = &[
            headers[8], headers[9], headers[10], headers[11], 
            headers[12], headers[13], headers[14], headers[15],
            headers[16]
        ];
        let headers_3 = &[
            headers[16], headers[17], headers[18], headers[19], 
            headers[20], headers[21], headers[22], headers[23],
            headers[24]
        ];
        let headers_4 = &[
            headers[24], headers[25], headers[26], headers[27], 
            headers[28], headers[29], headers[30], headers[31],
            headers[32]
        ];
        let headers_5 = &[
            headers[32], headers[33], headers[34], headers[35], 
            headers[36], headers[37], headers[38], headers[39],
            headers[40]
        ];
        let headers_6 = &[
            headers[40], headers[41], headers[42], headers[43], 
            headers[44], headers[45], headers[46], headers[47],
            headers[48]
        ];
        let headers_7 = &[
            headers[48], headers[49], headers[50], headers[51], 
            headers[52], headers[53], headers[54], headers[55],
            headers[56]
        ];
        let headers_8 = &[
            headers[56], headers[57], headers[58], headers[59], 
            headers[60], headers[61], headers[62], headers[63],
            headers[64]
        ];

        // Compile base layer circuit
        let compile_now = std::time::Instant::now();
        let (l0_data, targets) = compile_l1_circuit_flex(num_headers).unwrap();
        let compile_elapsed = compile_now.elapsed().as_millis();
        println!("Circuit compilation took {compile_elapsed:?}ms");

        let proof_now = std::time::Instant::now();

        let proof1 = run_l1_circuit_flex(&l0_data, &targets, headers_1, num_headers).unwrap();
        println!("stage 0, batch 1");

        let proof2 = run_l1_circuit_flex(&l0_data, &targets, headers_2, num_headers).unwrap();
        println!("stage 0, batch 2");

        let proof3 = run_l1_circuit_flex(&l0_data, &targets, headers_3, num_headers).unwrap();
        println!("stage 0, batch 3");

        let proof4 = run_l1_circuit_flex(&l0_data, &targets, headers_4, num_headers).unwrap();
        println!("stage 0, batch 4");

        let proof5 = run_l1_circuit_flex(&l0_data, &targets, headers_5, num_headers).unwrap();
        println!("stage 0, batch 5");

        let proof6 = run_l1_circuit_flex(&l0_data, &targets, headers_6, num_headers).unwrap();
        println!("stage 0, batch 6");

        let proof7 = run_l1_circuit_flex(&l0_data, &targets, headers_7, num_headers).unwrap();
        println!("stage 0, batch 7");

        let proof8 = run_l1_circuit_flex(&l0_data, &targets, headers_8, num_headers).unwrap();
        println!("stage 0, batch 8");

        let proof_merge_1 = compile_and_run_ln_circuit_flex(
            vec![proof1, proof2, proof3, proof4],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            4,
        )
        .unwrap();
        println!("stage 1, batch 1");

        let proof_merge_2 = compile_and_run_ln_circuit_flex(
            vec![proof5, proof6, proof7, proof8],
            &l0_data.verifier_only,
            &l0_data.common,
            false,
            4,
        )
        .unwrap();
        println!("stage 1, batch 2");

        let (final_proof, data) = compile_and_run_ln_circuit_flex(
            vec![proof_merge_1.0.unwrap(), proof_merge_2.0.unwrap()],
            &proof_merge_1.1.verifier_only,
            &proof_merge_1.1.common,
            false,
            2,
        )
        .unwrap();
        println!("stage 2, batch 0");

        let proof_elapsed = proof_now.elapsed().as_millis();
        println!("Proof generation and layering took {proof_elapsed:?}ms");

        let expected_end_hash = "00000000ebff91c88984bff39511f544a1c4ef6ec4f33e2ea531e47c2685628e";
        let end_hash_field = final_proof.clone().unwrap().public_inputs[256..512].to_vec();
        let mut end_hash_bits = Vec::new();
        for i in 0..end_hash_field.len() {
            end_hash_bits.push(end_hash_field[end_hash_field.len() - i - 1].to_canonical_u64() != 0);
        }
        let end_hash = bits_to_hex(&end_hash_bits).to_lowercase();
        assert_eq!(end_hash, expected_end_hash);

        println!("Verifying final proof...");
        data.verify(final_proof.unwrap())?;
        println!("Final proof verified!");

        Ok(())
    }

    fn bits_to_hex(bits: &[bool]) -> String {
        bits.chunks(8)
            .map(|chunk| {
                let byte = chunk.iter().enumerate().fold(0, |acc, (i, &bit)| acc | ((bit as u8) << i));
                format!("{:02X}", byte)
            })
            .collect::<Vec<String>>()
            .concat()
    }
}
