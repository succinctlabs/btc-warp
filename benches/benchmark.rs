use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use dotenv::dotenv;
use rand::Rng;
use tokio::runtime::Builder;
use btc_warp::proofs::generators::compute;

async fn bench_precomputed() {
    let mut rng = rand::thread_rng();

    let pf_per_layer = vec![8, 4, 2, 1];
    let pfs = vec![64, 8, 1];
    let layer = rng.gen_range(0..3);
    let index = rng.gen_range(0..pf_per_layer[layer+1]);
    let postfix = "test/flex/".to_string();
    match compute(layer, index, pf_per_layer[0..3].to_vec(), pfs, postfix).await {
        Ok(_) => (),
        Err(e) => panic!("Error generating precomputed proofs: {:#?}", e),
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    dotenv().ok();

    let mut group = c.benchmark_group("precomputed");
    group.sample_size(10);

    let rt = Builder::new_multi_thread().enable_all().build().unwrap();

    group.bench_function("precomputed", |b| {
        b.to_async(&rt).iter(|| bench_precomputed())
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
