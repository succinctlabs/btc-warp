#![feature(array_methods, array_chunks)]
pub mod blocks;
pub mod circuits;
pub mod client;
pub mod proofs;

#[macro_use]
extern crate rocket;
use dotenv::dotenv;

#[launch]
pub fn rocket() -> _ {
    dotenv().ok();

    rocket::build()
        .mount(
            "/light-client",
            routes![client::get_block_headers_range]
        )
}
