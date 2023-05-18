use anyhow::{anyhow, Result};
use nakamoto::chain::{BlockHash, BlockHeader};
use nakamoto::chain::store::Store;
use nakamoto::common::bitcoin_hashes::Hash;

use crate::client::StoreConfig;

pub fn get_block_headers_for_range(
    config: StoreConfig,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<BlockHeader>> {
    if from_height > to_height {
        return Err(anyhow!("from_height must be less than or equal to to_height"));
    }

    let store = config.to_file();

    let mut blocks = Vec::new();
    for i in from_height..to_height {
        let block = store.get(i);
        match block {
            Ok(b) => blocks.push(b),
            Err(e) => return Err(anyhow!("Block at height {i:?} not found: {e:#?}"))
        }
    }

    Ok(blocks)
}

pub struct ParentHashAndHeaders {
    pub parent_hash: BlockHash,
    pub headers: Vec<BlockHeader>,
}

pub fn get_parent_hash_and_headers(
    config: StoreConfig,
    from_height: u64,
    to_height: u64,
) -> Result<ParentHashAndHeaders> {
    let fetch_from_height = if from_height > 0 { from_height - 1 } else { 0 };

    let mut headers = get_block_headers_for_range(config, fetch_from_height, to_height)?;

    let parent_hash = if from_height > 0 {
        let parent_header = headers.remove(0);
        parent_header.block_hash()
    } else {
        BlockHash::from_slice(&vec![0u8; 32])?
    };

    Ok(ParentHashAndHeaders {
        parent_hash,
        headers,
    })
}


mod tests {
    use anyhow::{anyhow, Result};
    use rand::Rng;

    use crate::client::StoreConfig;
    use crate::blocks::block_fetcher::{get_parent_hash_and_headers, ParentHashAndHeaders};

    #[test]
    fn test_parent_hash_and_headers_rand() -> Result<()> {
        let config = StoreConfig::default();

        let mut rng = rand::thread_rng();
        let start: u64 = rng.gen_range(0..=100_000 / 2);
        let end: u64 = rng.gen_range(100_000..=200_000);

        let fetched = get_parent_hash_and_headers(config.clone(), start, end);

        match fetched {
            Ok(f) => {
                assert!(f.headers.len() == (end - start) as usize);
                Ok(())
            },
            Err(e) => Err(anyhow!("Failed to fetch parent hash and headers: {e:#?}")),
        }
    }
}
