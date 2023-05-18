use std::cmp;
use std::iter::repeat;

use anyhow::{anyhow, Result};

use crate::client::ApiResponse;
use crate::proofs::s3_pusher::S3Pusher;

const LC_API_BLOCKS_ENDPOINT: &str = "http://btc2.succinct.xyz/light-client/blocks";

// Fetch blocks from light client API
// Very basic error handling to make sure request has all the headers needed
pub async fn fetch_blocks(start: u64, end: u64) -> Result<String> {
    let url = format!("{}?start={}&end={}", LC_API_BLOCKS_ENDPOINT, start, end);
    match reqwest::get(url).await {
        Ok(res) => {
            let res = res.json::<ApiResponse>().await?;
            if res.error.is_some() {
                let err = res.error.unwrap();
                return Err(anyhow!(
                    "Failed to fetch headers, error code {}, {}",
                    res.code,
                    err
                ));
            }
            match res.headers {
                Some(h) => {
                    if h.len() as u64 == (end - start) * 160 {
                        Ok(h)
                    } else {
                        Err(anyhow!(
                            "Failed to fetch headers: invalid headers",
                        ))
                    }
                }
                None => {
                    Err(anyhow!("Failed to fetch headers: no headers"))
                }
            }
        }
        Err(e) => {
            Err(anyhow!("Failed to fetch headers: {:#?}", e))
        }
    }
}

// Fetch blocks from light client API with the following conditions:
// Range from [start, min(end, max)] and ensure length is `length`
// If min(end, max) - start < length, fill rest of headers with dummy headers
// TODO: THOROUGHLY TEST THIS FUNCTION
pub async fn fetch_blocks_lte(
    start: usize,
    end: usize,
    max: usize,
    length: usize,
) -> Result<Vec<String>> {
    let mut start_search = start;
    let mut end_search = cmp::min(end, max) + 1;
    let diff = if end_search - end == 0 {
        1
    } else {
        end - (end_search - 1)
    };
    if start_search > end_search {
        start_search = 0;
        end_search = 1;
    }

    let h = match fetch_blocks(start_search as u64, end_search as u64).await {
        Ok(hs) => hs,
        Err(e) => {
            return Err(e);
        }
    };
    let mut headers = h
        .chars()
        .collect::<Vec<char>>()
        .chunks(160)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>();

    if diff == 0 && headers.len() == length {
        return Ok(headers);
    }

    let dummy = match fetch_blocks(0u64, 1u64).await {
        Ok(hs) => hs,
        Err(e) => {
            return Err(e);
        }
    };
    let mut dummy_headers = dummy
        .chars()
        .collect::<Vec<char>>()
        .chunks(160)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<String>>();

    dummy_headers = repeat(dummy_headers[0].clone())
        .take(length - headers.len() - dummy_headers.len() + 1)
        .collect::<Vec<_>>();
    headers.append(&mut dummy_headers);

    Ok(headers)
}

// Fetch proofs from S3 bucket
pub async fn fetch_proofs_s3(
    s3: S3Pusher,
    layer_num: usize,
    start: usize,
    end: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut pfs = Vec::new();
    for i in start..end {
        let pf = s3
            .pull_bytes(&format!("layer_{:0>10}/proof_{:0>10}", layer_num, i))
            .await?;
        pfs.push(pf);
    }
    Ok(pfs)
}

pub fn leaf_to_root_path(leaf_idx: usize, proofs_per_layer: &Vec<usize>) -> Vec<usize> {
    let mut path = Vec::new();
    let mut idx = leaf_idx;
    for i in 0..proofs_per_layer.len() {
        let sub = idx > 0 && idx % proofs_per_layer[i] == 0;
        idx = idx / proofs_per_layer[i];
        if sub { 
            idx -= 1;
        }
        path.push(idx);
    }
    path
}

pub fn bits_to_hex(bits: &[bool]) -> String {
    bits.chunks(8)
        .map(|chunk| {
            let byte = chunk
                .iter()
                .enumerate()
                .fold(0, |acc, (i, &bit)| acc | ((bit as u8) << i));
            format!("{:02X}", byte)
        })
        .collect::<Vec<String>>()
        .concat()
}
