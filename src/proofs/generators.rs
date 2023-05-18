use anyhow::{anyhow, bail, Result};
use nakamoto::common::bitcoin_hashes::hex::ToHex;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::blocks::block_fetcher::get_block_headers_for_range;
use crate::client::StoreConfig;
use crate::proofs::constants::{N, NUM_PROOFS};
use crate::proofs::helper::{
    bits_to_hex, 
    leaf_to_root_path, 
    fetch_proofs_s3,
    fetch_blocks_lte,
};
use crate::proofs::provers::HistoryProver;
use crate::proofs::s3_pusher::S3Pusher;

fn get_job_id() -> Result<String> {
    let job_id = std::env::var("AWS_BATCH_JOB_ID").unwrap();
    let split: Vec<&str> = job_id.split(':').collect();
    if split.len() != 2 {
        bail!("Bad job id length");
    }

    Ok(split[0].to_owned())
}

// Handler function
// Dispatch calls to precompute leaf or node proofs accordingly
pub async fn compute(
    layer_num: usize,
    index: usize,
    child_proofs: Vec<usize>,
    num_proofs: Vec<usize>,
    postfix: String,
) -> Result<()> {
    if child_proofs.len() != num_proofs.len() {
        return Err(anyhow!("Proofs per layer and factors must be same length"));
    }
    if index > child_proofs[layer_num] {
        return Err(anyhow!("G-index must be less than proofs per layer"));
    }

    let s3 = S3Pusher::new("proofs/".to_string() + &postfix).await.unwrap();
    log::info!("Instantiated S3 client");

    let prover = HistoryProver::new(layer_num, &child_proofs.clone());

    let num_proof = num_proofs[layer_num];

    if layer_num != 0 {
        let num_child_proof = child_proofs[layer_num];
        let offset = index * num_proof * num_child_proof;

        for i in 0..num_proof {
            let start_idx = offset + i * num_child_proof;
            let end_idx = offset + (i + 1) * num_child_proof;

            if index * num_child_proof + i >= N[layer_num] {
                log::info!(
                    "Skipping {} (>= {})",
                    index * num_child_proof + i,
                    N[layer_num]
                );
                continue;
            }

            let children = match fetch_proofs_s3(s3.clone(), layer_num - 1, start_idx, end_idx).await {
                Ok(p) => p,
                Err(e) => {
                    return Err(e);
                }
            };
            log::info!("Fetched proofs {} to {}", start_idx, end_idx);

            match compute_node(s3.clone(), &prover, children, layer_num, index).await {
                Ok(_) => log::info!("Precomputed node proof for block {}", index),
                Err(e) => {
                    return Err(e);
                }
            }
        }
    } else {
        // For leaf case, we want to launch (total number of leafs) / (child_proofs[0] * num_proof) jobs
        let num_blocks = child_proofs[0];
        let offset = index * num_proof * (num_blocks - 1);
        for i in 0..num_proof {
            let start = offset + i * (num_blocks - 1);
            let end = offset + (i + 1) * (num_blocks - 1);

            if index * num_blocks + i > N[layer_num] {
                log::info!(
                    "Skipping {} (>= {})",
                    index * num_blocks + i,
                    N[layer_num]
                );
                continue;
            }

            let headers = match fetch_blocks_lte(start, end, NUM_PROOFS, num_blocks).await {
                Ok(hs) => hs,
                Err(e) => {
                    return Err(e);
                }
            };
            log::info!("Fetched headers from {start} to {end}");

            match compute_leaf(s3.clone(), &prover, headers, layer_num, index).await {
                Ok(_) => log::info!("Precomputed leaf proof for block {}", index),
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
    
    Ok(())
}

// Precompute leaf proof for base layer in recursive proof tree
pub async fn compute_leaf(
    s3: S3Pusher, 
    prover: &HistoryProver, 
    headers: Vec<String>, 
    layer: usize, 
    index: usize,
) -> Result<()> {
    let proof = prover.prove_headers_string(&headers);
    s3.push_bytes(
        &format!("layer_{:0>10}/proof_{:0>10}", layer, index),
        proof,
    ).await
}

// Precompute node proof for non-base layer in recursive proof tree
pub async fn compute_node(
    s3: S3Pusher, 
    prover: &HistoryProver, 
    child_proofs: Vec<Vec<u8>>, 
    layer: usize, 
    index: usize
) -> Result<()> {
    let proof = prover.prove_headers_layer(child_proofs);
    s3.push_bytes(
        &format!("layer_{:0>10}/proof_{:0>10}", layer, index),
        proof,
    ).await
}

// Update path from leaf proof to root proof with new block
pub async fn prove_next_block(
    block_index: usize,
    child_proofs: Vec<usize>,
    postfix: String,
) -> Result<()> {
    let s3 = S3Pusher::new("proofs/".to_string() + &postfix).await.unwrap();
    log::info!("Instantiated S3 client");

    let mut adjusted_proofs = child_proofs.clone();
    adjusted_proofs[0] -= 1;
    let path_indices = leaf_to_root_path(block_index, &adjusted_proofs);
    // log::info!("\tPath indices: {:?}", path_indices);

    for layer in 0..child_proofs.len() {
        let prover = HistoryProver::new(layer, &child_proofs);
        let idx = path_indices[layer];

        if layer != 0 {
            let start_idx = child_proofs[layer] * idx;
            let end_idx = child_proofs[layer] * (idx + 1);

            let proofs = match fetch_proofs_s3(s3.clone(), layer - 1, start_idx, end_idx).await {
                Ok(p) => p,
                Err(e) => {
                    return Err(e);
                }
            };
            log::info!("\tFetched existing proofs for layer {layer}");

            match compute_node(s3.clone(), &prover, proofs, layer, idx).await {
                Ok(_) => log::info!("Precomputed node proof for block {}", idx),
                Err(e) => {
                    return Err(e);
                }
            }
            log::info!("\tMerged proofs for layer {layer}");
        } else {
            log::info!("Index is {}", block_index);
            let start = (block_index / child_proofs[layer]) * (child_proofs[layer] - 1);
            let end = block_index;

            let headers = match fetch_blocks_lte(start, end, block_index, child_proofs[layer]).await {
                Ok(h) => h,
                Err(e) => {
                    return Err(e);
                }
            };
            log::info!("\tUnpacked headers");

            match compute_leaf(s3.clone(), &prover, headers, layer, idx).await {
                Ok(_) => log::info!("Precomputed leaf proof for block {}", idx),
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
    
    Ok(())
}

// Function to take root proof at given layer number and returning block height
// of end hash. Represents the last block that the proof verifies.
pub async fn root_proof_to_block_height(
    layer_num: usize,
    postfix: String,
    pf_per_layer: Vec<usize>,
) -> Result<u64> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let s3 = S3Pusher::new("proofs/".to_string() + &postfix).await.unwrap();
    log::info!("Instantiated S3 client");

    let store_config = StoreConfig::default();

    let proof_bytes = s3.pull_bytes(
        &format!("layer_{:0>10}/proof_{:0>10}", layer_num, 0)
    ).await.unwrap();
    log::info!("Fetch proof");

    let prover = HistoryProver::new(layer_num+1, &pf_per_layer);

    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        proof_bytes, 
        &prover.last_circuit_data.common
    ).unwrap();

    // Get end hash from proof outputs
    let end_hash_field = proof.public_inputs[256..512].to_vec();
    let mut end_hash_bits = Vec::new();
    for i in 0..end_hash_field.len() {
        end_hash_bits.push(end_hash_field[end_hash_field.len() - i - 1].to_canonical_u64() != 0);
    }
    let end_hash = bits_to_hex(&end_hash_bits).to_lowercase();

    let max_idx = N[0];

    // Iterate backwards with assumption that tree is more than half full, so more efficient (slightly)
    let block_headers = get_block_headers_for_range(store_config.clone(), 0, (max_idx+1) as u64).unwrap();
    for i in 0..block_headers.len() {
        let block_header = block_headers[max_idx - i].clone();
        let block_hash = block_header.block_hash().to_hex();
        if block_hash == end_hash {
            return Ok((max_idx - i) as u64);
        }
    }

    Err(anyhow!("Could not find block height for root proof"))
}

mod tests {
    use anyhow::Result;
    use log::LevelFilter;
    use env_logger::Builder;
    use dotenv::dotenv;
    use nakamoto::chain::BlockHeader;

    use crate::blocks::block::Header;
    use crate::blocks::block_fetcher::{ParentHashAndHeaders, get_parent_hash_and_headers};
    use crate::proofs::generators::{compute, prove_next_block, root_proof_to_block_height, N};
    use crate::proofs::constants::NUM_PROOFS;

    #[tokio::test]
    async fn test_proof_merging() -> Result<()> {
        setup_logger();
        dotenv().ok();

        let postfix = "test/flex/".to_string();
        let child_proofs = vec![9, 4, 2];
        let num_proofs = vec![1, 1, 1];
        log::info!("Proof per layer: {:?}", child_proofs);

        for i in 0..child_proofs.len() {
            for j in 0..N[i] {
                if j >= child_proofs[i] {
                    continue;
                }
                match compute(i, j, child_proofs.clone(), num_proofs.clone(), postfix.clone()).await {
                    Ok(_) => (),
                    Err(e) => {
                        log::error!("Error: {}", e);
                        return Err(e);
                    }
                }
            }
        }

        let block_height = root_proof_to_block_height(2, postfix, vec![9, 4, 2, 1]).await?;
        assert_eq!(block_height, NUM_PROOFS as u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_next_proof() -> Result<()> {
        // Assume precomputed proofs are already generated
        setup_logger();
        dotenv().ok();

        let postfix = "test/flex/".to_string();
        let index = NUM_PROOFS+1;
        let pf_per_layer = vec![9, 4, 2];

        prove_next_block(index, pf_per_layer, postfix.clone()).await?;
        
        let block_height = root_proof_to_block_height(2, postfix, vec![8, 4, 2, 1]).await?;
        assert_eq!(block_height as usize, index);

        Ok(())
    }

    #[tokio::test]
    async fn test_root_proof_to_block_height() -> Result<()> {
        setup_logger();
        dotenv().ok();

        let postfix = "test/flex/".to_string();
        let pf_per_layer = vec![9, 4, 2, 1];
        let block_height = root_proof_to_block_height(2, postfix, pf_per_layer).await?;
        assert_eq!(block_height, 62);
        Ok(())
    }

    fn setup_logger() {
        let mut builder = Builder::new();
        builder.filter_level(LevelFilter::Info);
        builder.init();
    }
}
