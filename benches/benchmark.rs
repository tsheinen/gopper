use criterion::{black_box, criterion_group, criterion_main, Criterion};
use gopper::gadgets;

const BYTES: &[u8; 6616616] = include_bytes!("../tests/bins/libc6_2.35-0ubuntu3.1_amd64.so");

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("decode libc", |b| {
        b.iter(|| {
            gadgets(black_box(BYTES))
                .expect("decoded without errors")
                .take(100)
                .count()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
