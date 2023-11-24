use amaze::amf::{
    franking::{frank, judge, keygen, verify},
    AMFRole,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("amf");
    group.significance_level(0.1).sample_size(1000);

    // 0. Initialize a Sender
    let (sender_public_key, sender_secret_key) = keygen(AMFRole::Sender);
    // 1. Initialize a Recipient
    let (recipient_public_key, recipient_secret_key) = keygen(AMFRole::Recipient);
    // 2. Initialize a Judge
    let (judge_public_key, judge_secret_key) = keygen(AMFRole::Judge);

    // 3. Initialize a message
    let message = b"hello world!";

    // 4. Frank the message
    let amf_signature = frank(
        sender_secret_key,
        sender_public_key,
        recipient_public_key,
        judge_public_key,
        message,
    );

    group.bench_function("keygen", |b| b.iter(|| keygen(AMFRole::Sender)));
    group.bench_function("franking", |b| {
        b.iter(|| {
            frank(
                black_box(sender_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(judge_public_key),
                black_box(message),
            )
        })
    });
    group.bench_function("verifying", |b| {
        b.iter(|| {
            verify(
                black_box(recipient_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(judge_public_key),
                black_box(message),
                black_box(amf_signature),
            )
        })
    });
    group.bench_function("judging", |b| {
        b.iter(|| {
            judge(
                black_box(judge_secret_key),
                black_box(sender_public_key),
                black_box(recipient_public_key),
                black_box(judge_public_key),
                black_box(message),
                black_box(amf_signature),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
