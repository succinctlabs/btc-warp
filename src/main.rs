use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use dotenv::dotenv;
use env_logger::Builder;
use log::LevelFilter;

use btc_warp::{
    proofs::generators::{compute, prove_next_block},
    rocket
};

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Historical {
        #[clap(short, long, required=true)]
        layer: usize,
        #[clap(short, long, required=true)]
        index: usize,
        #[clap(short, long, num_args=1.., value_delimiter=',', required=true)]
        child_proofs_per_layer: Vec<usize>,
        #[clap(short, long, num_args=1.., value_delimiter=',', required=true)]
        num_proofs_per_layer: Vec<usize>,
        #[clap(short, long)]
        postfix: String,
    },
    NextBlock {
        #[clap(short, long, required=true)]
        block_index: usize,
        #[clap(short, long, num_args=1.., value_delimiter=',', required=true)]
        child_proofs_per_layer: Vec<usize>,
        #[clap(short, long)]
        postfix: String,
    },
    LcApi,
    LightClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut builder = Builder::new();
    builder.filter_level(LevelFilter::Info);
    builder.init();

    dotenv().ok();

    let args = Args::parse();
    log::info!("Args: {:#?}", args);
    match args.cmd {
        SubCommand::Historical { 
            layer, 
            index, 
            child_proofs_per_layer, 
            num_proofs_per_layer,
            postfix, 
        } => {
            log::info!("Generating historical proof for layer {} and index {}", layer, index);
            match compute(layer, index, child_proofs_per_layer, num_proofs_per_layer, postfix).await {
                Ok(_) => {},
                Err(e) => {
                    return Err(anyhow!("Error generating historical proof: {:#?}", e));
                },
            }
        },
        SubCommand::NextBlock { 
            block_index, 
            child_proofs_per_layer,
            postfix 
        } => {
            log::info!("Generating next block proof for index {}", block_index);
            match prove_next_block(block_index, child_proofs_per_layer, postfix).await {
                Ok(_) => {},
                Err(e) => {
                    return Err(anyhow!("Error generating next block proof: {:#?}", e));
                },
            }
        },
        SubCommand::LcApi => {
            log::info!("Starting light client RPC API");
            match rocket().launch().await {
                Ok(_) => {},
                Err(e) => {
                    return Err(anyhow!("Error launching rocket: {:#?}", e));
                },
            }
        },
        SubCommand::LightClient => {
            log::info!("Starting light client");
            let (lc_config, client) = btc_warp::client::make_lc().unwrap();

            match client.run(lc_config) {
                Ok(_) => {},
                Err(e) => {
                    return Err(anyhow!("Error running light client: {:#?}", e));
                },
            }
        },
    }

    Ok(())
}
