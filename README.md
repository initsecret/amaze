# `amaze`: faster asymmetric message franking

[![Rust](https://github.com/sgmenda/amaze/actions/workflows/rust.yml/badge.svg)](https://github.com/sgmenda/amaze/actions/workflows/rust.yml)

_Experimental Rust implementation of Asymmetric Message Franking_

> Nirvan Tyagi, Paul Grubbs, Julia Len, Ian Miers, and Thomas Ristenpart. _Asymmetric Message Franking: Content Moderation for Metadata-Private End-to-End Encryption_. Crypto 2019. [ia.cr/2019/565](https://ia.cr/2019/565)

## Security (Or Lack Thereof)

This was hacked together in a weekend in 2022 when I knew even less cryptography than I know today. It is almost certainly insecure.

## About and Organization

`amaze` is an experimental implementation of [Asymmetric Message Franking](https://ia.cr/2019/565). It uses the [Ristretto group](https://ristretto.group/) as the underlying cyclic group, and includes implementations of the underlying proof of knowledge schemes.

1. Module `pok` implements the standard proofs of knowledge that underlie AMFs.
2. Module `amf` implements asymmetric message franking.

## Example

```rust
// 0. Initialize a Sender
let (sender_public_key, sender_secret_key) = amaze::amf::keygen(amaze::amf::AMFRole::Sender);
// 1. Initialize a Recipient
let (recipient_public_key, recipient_secret_key) = amaze::amf::keygen(amaze::amf::AMFRole::Recipient);
// 2. Initialize a Judge
let (judge_public_key, judge_secret_key) = amaze::amf::keygen(amaze::amf::AMFRole::Judge);

// 3. Initialize a message
let message = b"hello world!";

// 4. The sender franks the message
let amf_signature = amaze::amf::frank(
    sender_secret_key,
    sender_public_key,
    recipient_public_key,
    judge_public_key,
    message,
);
println!("amf_signature: {:?}", amf_signature);

// 5. The recipient verifies the message to be authentic
let verification_result = amaze::amf::verify(
    recipient_secret_key,
    sender_public_key,
    recipient_public_key,
    judge_public_key,
    message,
    amf_signature,
);
assert!(verification_result);

// 6. On report, the judge judges the message to be authentic
let judging_result = amaze::amf::judge(
    judge_secret_key,
    sender_public_key,
    recipient_public_key,
    judge_public_key,
    message,
    amf_signature,
);
assert!(judging_result);
```

## Usage

### Building and Running Benchmarks Locally

If you have a local rust toolchain, then this should be as easy as

```shell
cargo build
cargo bench
```

### Benchmarking on Android

Now, this is a challenge.

First, obtain an android phone and a cord to connect it to your computer.

Second, get [android studio](https://developer.android.com/studio) and use its SDK Manager to install the [Android NDK](https://developer.android.com/ndk) (we will be using this for cross-compiling) and the [SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools). Ensure that the SDK platform tools (specifically `adb`) are in your `PATH` (we will be using this to communicate with the android device.)

Third, install the relevant target (for my Pixel, this was `aarch64-linux-android`), and get [cargo-ndk](https://github.com/bbqsrc/cargo-ndk) to simplify the cross-compilation process.

_Aside._ I couldn't get criterion to work on android, so I wrote a hacky pure rust benchmark (`hacky_bench_for_android`) just for android.

Anyho, for my Pixel, these were the steps to install and cross-compile.

```shell
cargo install cargo-ndk
rustup target add aarch64-linux-android
cargo ndk --target aarch64-linux-android build --bench hacky_bench_for_android --release
```

Once we have a cross-compiled binary, we can push it to the android device and run the benchmark.

```shell
cp target/aarch64-linux-android/release/deps/hacky_bench_for_android-[tab to complete] hacky
adb -d push hacky /data/local/tmp/bench
adb -d shell /data/local/tmp/bench
```

### Preliminary Benchmarks

| Algorithm   | MacBook Pro, 16", M2 Pro | MacBook Pro, 13", M1 | Pixel 5a |
| :---------- | :----------------------- | :------------------- | :------- |
| `keygen`    | 26.296 us                | 30.395 us            | 167 us   |
| `franking`  | 306.73 us                | 352.52 us            | 1922 us  |
| `verifying` | 306.16 us                | 351.62 us            | 1918 us  |
| `judging`   | 305.64 us                | 351.43 us            | 1918 us  |

---

#### Thanks

- Thanks to Armin Namavari and Nirvan Tyagi for helpful discussions.
- Thanks to Nirvan Tyagi and Julia Len for the [nirvantyagi/orca](https://github.com/nirvantyagi/orca), and especially the [README.md](https://github.com/nirvantyagi/orca/blob/dec67694f7590f20c3aae72367ae38541f5eaa03/README.md) which I found incredibly helpful when trying to run the benchmark on android.

#### License

`amaze` is licensed under the [Apache 2.0 license](/LICENSE).

#### Citation

If you use `amaze` in research, in addition to citing the [AMF paper](https://ia.cr/2019/565), please cite this implementation specifically using the following bibtex. This will help me track if people care about this, and accordingly improve it.

```bibtex
@misc{amaze,
  author = {amaze contributors},
  title = {\texttt{amaze}: faster asymmetric message franking},
  year = {2023},
  url = {https://github.com/sgmenda/amaze},
}
```
