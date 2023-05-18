use btc_warp::{
    blocks::{
        block::Header,
        block_fetcher::get_block_headers_for_range,
    },
    client::StoreConfig
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = StoreConfig::default();
    let headers = get_block_headers_for_range(config.clone(), 0, 128)?
        .into_iter()
        .map(|bh| Header::from(bh))
        .collect::<Vec<Header>>();
    let body = headers
        .iter()
        .map(|header| {
            let slice: Vec<u8> = Header::into(*header);
            format!("\"{}\"", hex::encode(&slice[..]))
        })
        .collect::<Vec<String>>()
        .join(",\n");
    println!("{}", body);
    Ok(())
}
