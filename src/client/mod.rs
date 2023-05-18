use std::net;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use nakamoto::chain::BlockHeader;
use nakamoto::chain::store::File;
use nakamoto::client::Client;
use nakamoto::client::Config as NakamotoConfig;
use nakamoto::client::Network::{self, Mainnet};
use nakamoto::net::poll::Reactor as NakamotoPollReactor;
use rocket::get;
use rocket::serde::json::{json, Value};
use serde::{Serialize, Deserialize};

use crate::blocks::block::Header;
use crate::blocks::block_fetcher::ParentHashAndHeaders;
use crate::blocks::block_fetcher::get_parent_hash_and_headers;

#[derive(Clone)]
pub struct StoreConfig {
    pub home: PathBuf,
    pub db: String,
    pub network: Network,
}

impl StoreConfig {
    pub fn to_file(self) -> File<BlockHeader> {
        let dir = self.home.join(".nakamoto").join(self.network.as_str());
        let genesis = self.network.genesis();
        let path = dir.join(self.db);
        File::open(path, genesis).unwrap()
    }

    pub fn get_db_path(self) -> String {
        let dir = self.home.join(self.network.as_str());
        let dir_path = dir.join(self.db);
        let str_path = dir_path.to_str().unwrap();
        str_path.to_string()
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            home: PathBuf::from_str("light-client/").unwrap(),
            db: "headers.db".to_string(),
            network: Mainnet,
        }
    }
}
 

type Reactor = NakamotoPollReactor<net::TcpStream>;

pub fn make_lc() -> Result<(NakamotoConfig, Client<Reactor>)> {
    let store_config = StoreConfig::default();
    let nakamoto_config = NakamotoConfig {
        root: store_config.home,
        ..NakamotoConfig::default()
    };

    let client = Client::<Reactor>::new()?;

    Ok((nakamoto_config, client))
}

pub fn run_lc(config: NakamotoConfig, client: Client<Reactor>) -> Result<()> {
    client.run(config)?;

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    pub code: usize,
    pub headers: Option<String>,
    pub error: Option<String>
}

#[get("/blocks?<start>&<end>")]
pub async fn get_block_headers_range(start: u64, end: u64) -> Option<Value> {
    log::info!("Getting block headers for range {} to {}", start, end);
    let store_config = StoreConfig::default();
    match get_parent_hash_and_headers(store_config, start, end) {
        Ok(ParentHashAndHeaders {
            parent_hash: _,
            headers: block_headers,
        }) => {
            let headers = Header::from_vec_blockheader(block_headers);
            let header_hexs = Header::to_hex_vec(headers);
            let headers_str = header_hexs
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>();
            let h = headers_str.join("");
            Some(json!({ 
                "code": 200,
                "headers": h 
            }))
        }
        Err(e) => {
            log::error!("Error: {:#?}", e);
            Some(json!({ 
                "code": 500,
                "error": format!("{:#?}", e)
            }))
        }
    }
}