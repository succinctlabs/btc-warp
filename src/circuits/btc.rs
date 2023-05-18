use std::ops::{AddAssign, MulAssign};

use crate::circuits::helper::{bits_to_biguint_target, byte_to_u32_target};
use crate::circuits::sha256::{make_sha256_circuit, Sha256Target};
use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_u32::gadgets::arithmetic_u32::U32Target;
use plonky2_u32::gadgets::multiple_comparison::list_le_u32_circuit;

const HASH_LEN_BITS: usize = 256;
const HASH_LEN_BYTES: usize = HASH_LEN_BITS / 8;
const HEADER_SIZE_BYTES: usize = 80 * 8;

pub struct HeaderTarget {
    pub header_bits: [BoolTarget; HEADER_SIZE_BYTES],
    pub threshold_bits: [BoolTarget; HASH_LEN_BITS],
    pub hash: [BoolTarget; HASH_LEN_BITS],
    pub work: BigUintTarget,
}

/// Verify one Bitcoin header
/// In this circuit, we must
///     1. Check block header hashes to a value less than threshold computed
///        from difficulty bits
///     2. Check difficulty is valid
pub fn make_header_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> HeaderTarget {
    let _f = builder._false();
    let mut header_bits = [_f; HEADER_SIZE_BYTES];
    for i in 0..HEADER_SIZE_BYTES {
        header_bits[i] = builder.add_virtual_bool_target_safe();
    }

    let (sha1_targets, return_hash) = calculate_return_hash(builder, header_bits);

    let threshold_bits = validate_threshold(builder, header_bits, sha1_targets);

    let work = calculate_work(builder, threshold_bits);

    return HeaderTarget {
        header_bits: header_bits,
        threshold_bits: threshold_bits,
        hash: return_hash,
        work: work,
    };
}

/// Validate return hash of header
/// Return hash := SHA256(SHA256(header))
fn calculate_return_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    header_bits: [BoolTarget; HEADER_SIZE_BYTES],
) -> (Sha256Target, [BoolTarget; HASH_LEN_BITS]) {
    // Compute h1 := SHA256(header)
    let sha1_targets = make_sha256_circuit(builder, header_bits.len() as u128);
    for i in 0..header_bits.len() {
        builder.connect(header_bits[i].target, sha1_targets.message[i].target);
    }

    // Compute h2 := SHA256(h1)
    let sha2_targets = make_sha256_circuit(builder, sha1_targets.digest.len() as u128);
    for i in 0..sha1_targets.digest.len() {
        builder.connect(
            sha1_targets.digest[i].target,
            sha2_targets.message[i].target,
        );
    }

    let _f = builder._false();
    let mut return_hash = [_f; HASH_LEN_BITS];
    for i in 0..HASH_LEN_BITS {
        return_hash[i] = builder.add_virtual_bool_target_safe();
        builder.connect(sha2_targets.digest[i].target, return_hash[i].target);
    }
    (sha1_targets, return_hash)
}

/// Target T := a special fp32 with no sign bit, 24 bit mantissa, and 8 bit exponent
/// Valid blocks must satisfy SHA256(block) < T
/// This function computes and validates the threshold T
/// Return threshold bits for other functions to use
fn validate_threshold<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    header_bits: [BoolTarget; HEADER_SIZE_BYTES],
    sha1_targets: Sha256Target,
) -> [BoolTarget; HASH_LEN_BITS] {
    let _zero = builder.zero();
    let _f = builder._false();

    // Extract difficulty exponent from header
    let difficulty_exp_bits = header_bits[600..608].to_vec();
    let difficulty_exp_int = byte_to_u32_target(builder, difficulty_exp_bits);

    // Assign threshold byte from header bytes
    let mut threshold_bytes = [_zero; 32];
    for i in 0..32 {
        threshold_bytes[i] = builder.add_virtual_target();
    }
    let mut assign_threshold_byte = |threshold_byte_index: u64, header_bit_index: usize| {
        let threshold_byte_idx = builder.constant(F::from_canonical_u64(threshold_byte_index));
        let access_idx = builder.sub(threshold_byte_idx, difficulty_exp_int.0);

        let header_byte = byte_to_u32_target(
            builder,
            header_bits[header_bit_index..header_bit_index + 8].to_vec(),
        );

        let threshold_byte = builder.random_access(access_idx, threshold_bytes.to_vec());
        builder.connect(threshold_byte, header_byte.0);
    };
    assign_threshold_byte(32, 592);
    assign_threshold_byte(33, 584);
    assign_threshold_byte(34, 576);

    // Ensure validity of threshold
    // Check 1: Ensure SHA256(block) < threshold
    let _zero = builder.zero();
    let mut sha1_bytes = [_zero; 32];
    for j in 0..HASH_LEN_BYTES {
        sha1_bytes[j] = builder.add_virtual_target();

        let byte_from_bits =
            byte_to_u32_target(builder, sha1_targets.digest[j * 8..(j + 1) * 8].to_vec()).0;
        builder.connect(sha1_bytes[j], byte_from_bits);
    }
    let is_less = list_le_u32_circuit(
        builder,
        threshold_bytes.into_iter().map(|x| U32Target(x)).collect(),
        sha1_bytes.into_iter().map(|x| U32Target(x)).collect(),
    );
    let one = builder._true();
    builder.connect(is_less.target, one.target);
    // Check 2: Ensure exponent and mantissa bytes are valid
    let threshold_bits = validate_mantissa(builder, threshold_bytes, difficulty_exp_int);

    threshold_bits
}

/// Validate mantissa and exponent bits of difficulty
fn validate_mantissa<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    threshold_bytes: [Target; HASH_LEN_BYTES],
    difficulty_exp_int: U32Target,
) -> [BoolTarget; HASH_LEN_BITS] {
    let _false = builder._false();
    let zero = builder.zero();
    let const32 = builder.constant(F::from_canonical_u32(32));

    // Prepare threshold bytes -> bits conversion
    let mut threshold_bits = [_false; HASH_LEN_BITS];
    for i in 0..HASH_LEN_BITS {
        threshold_bits[i] = builder.add_virtual_bool_target_safe();
    }

    // Check each threshold byte is maps to a mantissa byte or is zero
    // This is because above we only assigned threshold bytes to be the
    // 72-74th bits of the header
    for j in 0..HASH_LEN_BYTES {
        let const_index = builder.constant(F::from_canonical_u64(j as u64));

        let is_zero = builder.is_equal(threshold_bytes[j], zero);

        let index1 = builder.sub(const32, difficulty_exp_int.0);
        let is_first_mantissa_byte = builder.is_equal(const_index, index1);

        let index2 = builder.add_const(index1, F::ONE);
        let is_second_mantissa_byte = builder.is_equal(const_index, index2);

        let index3 = builder.add_const(index2, F::ONE);
        let is_third_mantissa_byte = builder.is_equal(const_index, index3);

        let range_check1 = builder.add(
            is_first_mantissa_byte.target,
            is_second_mantissa_byte.target,
        );
        let is_in_range = builder.add(range_check1, is_third_mantissa_byte.target);
        let in_range_or_zero = builder.add(is_zero.target, is_in_range);
        let mistake_exists = builder.is_equal(in_range_or_zero, zero);
        builder.connect(mistake_exists.target, _false.target);

        // Constraint thresholds bits to map to threshold bytes
        let threshold_bits_to_byte =
            byte_to_u32_target(builder, threshold_bits[j * 8..(j + 1) * 8].to_vec()).0;
        builder.connect(threshold_bytes[j], threshold_bits_to_byte);
    }

    threshold_bits
}

/// Calculate work given threshold bits
/// Bitcoin's formula for work W is defined as
/// W := 2**256 // threshold
fn calculate_work<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    threshold_bits: [BoolTarget; 256],
) -> BigUintTarget {
    let _f = builder._false();

    let mut threshold_bits_copy = [_f; HASH_LEN_BITS];
    let mut numerator_bits = [_f; HASH_LEN_BITS];

    // Fast way to compute numerator := 2**256
    // BigUint math way is super slow
    for i in 0..HASH_LEN_BITS {
        numerator_bits[i] = builder.constant_bool(true);
        threshold_bits_copy[i] = builder.add_virtual_bool_target_safe(); // Will verify that input is 0 or 1
        builder.connect(threshold_bits[i].target, threshold_bits_copy[i].target);
    }

    let numerator_as_biguint = bits_to_biguint_target(builder, numerator_bits.to_vec());
    let denominator = bits_to_biguint_target(builder, threshold_bits_copy.to_vec());
    let work = builder.div_biguint(&numerator_as_biguint, &denominator);
    work
}

pub struct MultiHeaderTarget {
    pub headers: Vec<BoolTarget>,
    pub multi_threshold_bits: Vec<BoolTarget>,
    pub total_work: BigUintTarget,
    pub hashes: Vec<[BoolTarget; 256]>,
}

/// Verify several Bitcoin headers
/// In this circuit, we must
///     1. Check that block i's parent hash is the hash of block i-1
///     2. Check that the total work for the chain is valid
/// Need >= 2 headers for this circuit
pub fn make_multi_header_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    num_headers: usize,
) -> MultiHeaderTarget {
    if num_headers < 2 {
        panic!("Not enough headers to form a chain");
    }
    let mut multi_header_bits = Vec::new();
    for _ in 0..num_headers * HEADER_SIZE_BYTES {
        multi_header_bits.push(builder.add_virtual_bool_target_safe());
    }

    let mut multi_threshold_bits = Vec::new();
    for _ in 0..num_headers * HASH_LEN_BITS {
        multi_threshold_bits.push(builder.add_virtual_bool_target_safe());
    }

    let mut hashes = Vec::new();
    let mut work = Vec::new();

    // Verify each header and accumulate total work
    for h in 0..num_headers {
        let header_targets = make_header_circuit(builder);

        // Index into multiheader header bits to connect current header
        // header bits
        for i in 0..80 * 8 {
            builder.connect(
                header_targets.header_bits[i].target,
                multi_header_bits[(h * 8 * 80) + i].target,
            );
        }

        // Index into multiheader threshold bits to connect current header
        // threshold bits
        for i in 0..HASH_LEN_BITS {
            builder.connect(
                header_targets.threshold_bits[i].target,
                multi_threshold_bits[h * HASH_LEN_BITS + i].target,
            );
        }

        // Accumulate total work
        if h == 0 {
            work.push(header_targets.work);
        } else {
            work.push(builder.add_biguint(&work[h - 1], &header_targets.work));
        }

        // Connect parent hashes to verify connected chain
        hashes.push(header_targets.hash);
        if h > 0 {
            let claimed_prev_header = &multi_header_bits
                [(h * HEADER_SIZE_BYTES) + 4 * 8..(h * HEADER_SIZE_BYTES) + 36 * 8];
            for i in 0..HASH_LEN_BITS {
                builder.connect(hashes[h - 1][i].target, claimed_prev_header[i].target);
            }
        }
    }

    // [A, B, C, D]
    // [A, B] <-> [B, C] <-> [C, D]
    let total_work = builder.add_virtual_biguint_target(work[work.len() - 2].num_limbs());
    builder.connect_biguint(&work[work.len() - 2], &total_work);

    return MultiHeaderTarget {
        headers: multi_header_bits,
        multi_threshold_bits: multi_threshold_bits,
        total_work: total_work,
        hashes: hashes,
    };
}

/// Flexible version
pub struct MultiHeaderTargetFlex {
    pub headers: Vec<BoolTarget>,
    pub multi_threshold_bits: Vec<BoolTarget>,
    pub total_work: BigUintTarget,
    pub hashes: Vec<Vec<BoolTarget>>,
}

/// Verify several Bitcoin headers
/// In this circuit, we must
///     1. Check that block i's parent hash is the hash of block i-1
///     2. Check that the total work for the chain is valid
/// Need >= 2 headers for this circuit
pub fn make_multi_header_circuit_flex<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    num_headers: usize,
) -> MultiHeaderTargetFlex {
    if num_headers < 2 {
        panic!("Not enough headers to form a chain");
    }
    let mut multi_header_bits = Vec::new();
    for _ in 0..num_headers * HEADER_SIZE_BYTES {
        multi_header_bits.push(builder.add_virtual_bool_target_safe());
    }

    let mut multi_threshold_bits = Vec::new();
    for _ in 0..num_headers * HASH_LEN_BITS {
        multi_threshold_bits.push(builder.add_virtual_bool_target_safe());
    }

    let mut hashes: Vec<Vec<BoolTarget>> = Vec::new();
    let mut work = Vec::new();

    let _zero = builder.zero();
    let _one = builder.one();
    let _bu_zero = BigUint::new(vec![0]);
    let _biguint_zero = builder.constant_biguint(&_bu_zero);

    // Verify each header and accumulate total work
    for h in 0..num_headers {
        let header_targets = make_header_circuit(builder);

        // Index into multiheader header bits to connect current header
        // header bits
        for i in 0..80 * 8 {
            builder.connect(
                header_targets.header_bits[i].target,
                multi_header_bits[(h * 8 * 80) + i].target,
            );
        }

        // Index into multiheader threshold bits to connect current header
        // threshold bits
        for i in 0..HASH_LEN_BITS {
            builder.connect(
                header_targets.threshold_bits[i].target,
                multi_threshold_bits[h * HASH_LEN_BITS + i].target,
            );
        }

        // Connect parent hashes to verify connected chain
        let mut so_far = builder._true();
        let _f = builder._false();
        if h > 0 {
            let claimed_prev_header = &multi_header_bits
                [(h * HEADER_SIZE_BYTES) + 4 * 8..(h * HEADER_SIZE_BYTES) + 36 * 8];
            let curr_consistent =
                check_header_consistency(builder, &hashes[h - 1], claimed_prev_header);
            let so_far_t = builder.select(curr_consistent, so_far.target, _f.target);
            so_far = BoolTarget::new_unsafe(so_far_t);

            let mut curr_hash = [None; HASH_LEN_BITS];
            for i in 0..HASH_LEN_BITS {
                let connect_bit = builder.select(
                    so_far,
                    hashes[h - 1][i].target,
                    claimed_prev_header[i].target,
                );
                builder.connect(claimed_prev_header[i].target, connect_bit);

                let arr_bit = builder.select(
                    so_far,
                    header_targets.hash[i].target,
                    hashes[h - 1][i].target
                );
                curr_hash[i] = Some(BoolTarget::new_unsafe(arr_bit));
            }
            let tmp = curr_hash.map(|x| x.unwrap()).to_vec();
            hashes.push(tmp);

            let mut limbs = Vec::new();
            for i in 0..8 {
                let l = builder.select(so_far, header_targets.work.get_limb(i).0, _zero);
                limbs.push(U32Target(l));
            }
            let curr_work = BigUintTarget { limbs };
            work.push(builder.add_biguint(&work[h - 1], &curr_work));
        } else {
            hashes.push(header_targets.hash.to_vec());
            work.push(header_targets.work);
        }
    }

    // [A, B, C, D]
    // [A, B] <-> [B, C] <-> [C, D]
    let total_work = builder.add_virtual_biguint_target(work[work.len() - 2].num_limbs());
    builder.connect_biguint(&work[work.len() - 2], &total_work);

    return MultiHeaderTargetFlex {
        headers: multi_header_bits,
        multi_threshold_bits: multi_threshold_bits,
        total_work: total_work,
        hashes: hashes,
    };
}

fn check_header_consistency<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    h1: &[BoolTarget],
    h2: &[BoolTarget],
) -> BoolTarget {
    let consistent = builder.add_virtual_bool_target_safe();
    let mut so_far = builder.one();
    let f = builder.zero();
    for i in 0..256 {
        let eq = builder.is_equal(h1[i].target, h2[i].target);
        so_far = builder.select(eq, so_far, f);
    }
    builder.connect(consistent.target, so_far);
    consistent
}

pub fn to_bits(msg: Vec<u8>) -> Vec<bool> {
    let mut res = Vec::new();
    for i in 0..msg.len() {
        let char = msg[i];
        for j in 0..8 {
            if (char & (1 << 7 - j)) != 0 {
                res.push(true);
            } else {
                res.push(false);
            }
        }
    }
    res
}

pub fn compute_exp_and_mantissa(header_bits: Vec<bool>) -> (u32, u64) {
    let mut d = 0;
    for i in 600..608 {
        d += ((header_bits[i]) as u32) << (608 - i - 1);
    }
    let exp = 8 * (d - 3);
    let mut mantissa = 0;
    for i in 576..584 {
        mantissa += ((header_bits[i]) as u64) << (584 - i - 1);
    }
    for i in 584..592 {
        mantissa += ((header_bits[i]) as u64) << (592 - i - 1 + 8);
    }
    for i in 592..600 {
        mantissa += ((header_bits[i]) as u64) << (600 - i - 1 + 16);
    }

    (exp, mantissa)
}

pub fn compute_work(exp: u32, mantissa: u64) -> BigUint {
    let mut my_threshold_bits = Vec::new();
    for i in 0..256 {
        if i < 256 - exp
            && mantissa as u128 & (1u128 << (255u128 - (exp as u128) - (i as u128))) != 0
        {
            my_threshold_bits.push(true);
        } else {
            my_threshold_bits.push(false);
        }
    }
    let mut acc: BigUint = BigUint::new(vec![1]);
    let mut denominator: BigUint = BigUint::new(vec![0]);
    for i in 0..256 {
        if my_threshold_bits[255 - i] {
            denominator.add_assign(acc.clone());
        }
        acc.mul_assign(BigUint::new(vec![2]));
    }
    let numerator = acc;
    let correct_work = numerator / denominator;
    return correct_work;
}

#[cfg(test)]
mod tests {
    use std::ops::AddAssign;

    use anyhow::Result;
    use hex::decode;
    use num::BigUint;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_ecdsa::gadgets::biguint::{CircuitBuilderBiguint, WitnessBigUint};
    use plonky2_u32::gadgets::arithmetic_u32::CircuitBuilderU32;

    use crate::circuits::btc::{
        compute_exp_and_mantissa, compute_work, make_header_circuit, 
        make_multi_header_circuit_flex, make_multi_header_circuit, to_bits,
    };

    #[test]
    fn test_work() -> Result<()> {
        println!("{}", compute_work(0, 1));
        Ok(())
    }

    #[test]
    fn test_header_circuit() -> Result<()> {
        // let genesis_header = decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap();
        // This is the 500k header, not genesis
        let genesis_header = decode("000000201929eb850a74427d0440cf6b518308837566cd6d0662790000000000000000001f6231ed3de07345b607ec2a39b2d01bec2fe10dfb7f516ba4958a42691c95316d0a385a459600185599fc5c").unwrap();
        let header_bits = to_bits(genesis_header);
        // NOTE this is the reversed order of how it's displayed on block explorers
        // let expected_hash = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        let expected_hash = "045d94a1c33354c3759cc0512dcc49fd81bf4c3637fb24000000000000000000";
        let hash_bits = to_bits(decode(expected_hash).unwrap());

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_header_circuit(&mut builder);

        for i in 0..hash_bits.len() {
            if hash_bits[i] {
                builder.assert_one(targets.hash[i].target);
            } else {
                builder.assert_zero(targets.hash[i].target);
            }
        }

        let mut pw = PartialWitness::new();
        for i in 0..header_bits.len() {
            pw.set_bool_target(targets.header_bits[i], header_bits[i]);
        }

        let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
        println!("exp: {}, mantissa: {}", exp, mantissa);
        let correct_work = compute_work(exp, mantissa);
        // When you include the below line, the circuit should fail since correct work is wrong
        // correct_work.sub_assign(BigUint::new(vec![1]));

        for i in 0..256 {
            if i < 256 - exp
                && mantissa as u128 & (1u128 << (255u128 - exp as u128 - i as u128)) != 0
            {
                pw.set_bool_target(targets.threshold_bits[i as usize], true);
                print!("1");
            } else {
                pw.set_bool_target(targets.threshold_bits[i as usize], false);
                print!("0");
            }
        }
        println!("");

        let mut correct_work_target = builder.constant_biguint(&correct_work);
        for _ in 8 - correct_work_target.num_limbs()..8 {
            correct_work_target.limbs.push(builder.zero_u32());
        }
        builder.connect_biguint(&targets.work, &correct_work_target);

        let data = builder.build::<C>();
        let now = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let elapsed = now.elapsed().as_millis();
        println!("Proved the circuit in {} ms", elapsed);
        data.verify(proof)
    }

    #[test]
    fn test_multi_header_circuit() -> Result<()> {
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
        let _expected_hashes = [
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            "4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000",
            "bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a00000000",
            "4944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b58200000000",
            "85144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000",
            "fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000",
            "8d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a0313000000000",
            "4494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000",
            "c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000",
            "0508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000",
        ];

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_multi_header_circuit(&mut builder, num_headers);

        // Connect first hash in chain and check last hash in chain
        // If not a valid chain, then the last hash will be mismatched
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

        let data = builder.build::<C>();

        // post compile
        let mut total_work = BigUint::new(vec![0]);
        let mut pw = PartialWitness::new();

        for h in 0..num_headers {
            let header_bits = to_bits(decode(headers[h]).unwrap());
            for i in 0..80 * 8 {
                pw.set_bool_target(targets.headers[h * 80 * 8 + i], header_bits[i]);
            }

            let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
            let header_work = compute_work(exp, mantissa);
            if h != num_headers - 1 {
                total_work.add_assign(header_work);
            }

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

        pw.set_biguint_target(&targets.total_work, &total_work);

        println!("Built the circuit");
        let now = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let elapsed = now.elapsed().as_millis();
        println!("Proved the circuit in {} ms", elapsed);

        data.verify(proof)?;

        Ok(())
    }

    #[test]
    fn test_multi_header_flex_circuit() -> Result<()> {
        let num_headers = 10;
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            // "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
            // "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53"
        ];
        let _expected_hashes = [
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            "4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000",
            "bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a00000000",
            // "4944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b58200000000",
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            "85144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000",
            "fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000",
            "8d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a0313000000000",
            "4494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000",
            "c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000",
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
            // "0508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000",
        ];

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_multi_header_circuit_flex(&mut builder, num_headers);

        // Connect first hash in chain and check last hash in chain
        // If not a valid chain, then the last hash will be mismatched
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

        let data = builder.build::<C>();

        // post compile
        let mut total_work = BigUint::new(vec![0]);
        let mut pw = PartialWitness::new();

        for h in 0..num_headers {
            let header_bits = to_bits(decode(headers[h]).unwrap());
            for i in 0..80 * 8 {
                pw.set_bool_target(targets.headers[h * 80 * 8 + i], header_bits[i]);
            }

            let (exp, mantissa) = compute_exp_and_mantissa(header_bits);
            let header_work = compute_work(exp, mantissa);
            // if h != num_headers - 1 {
            if h < 3 {
                total_work.add_assign(header_work);
            }

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

        pw.set_biguint_target(&targets.total_work, &total_work);

        println!("Built the circuit");
        let now = std::time::Instant::now();
        let proof = data.prove(pw).unwrap();
        let elapsed = now.elapsed().as_millis();
        println!("Proved the circuit in {} ms", elapsed);
        println!("{:?}", proof.public_inputs);

        data.verify(proof)?;

        Ok(())
    }
}
