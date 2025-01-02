# chksum-sha2

[![crates.io](https://img.shields.io/crates/v/chksum-sha2?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-sha2)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/sha2/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/sha2/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-sha2?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-sha2/)
[![MSRV](https://img.shields.io/badge/MSRV-1.74.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/sha2/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-sha2/0.1.0/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-sha2/0.1.0)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/sha2?style=flat-square "LICENSE")](https://github.com/chksum-rs/sha2/blob/master/LICENSE)

An implementation of SHA-2 hash functions with a straightforward interface for computing digests of bytes, files, directories, and more.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-sha2 = "0.1.0"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-sha2
```

## Usage

Use the `chksum` function to calculate digest of file, directory and so on.

```rust
use chksum_sha2::sha2_256;

let file = File::open(path)?;
let digest = sha2_256::chksum(file)?;
assert_eq!(
    digest.to_hex_lowercase(),
    "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-sha2/).

## Features

Cargo features are used to enable or disable specific algorithm functions.

* `224` enables SHA-2 224, accessible via the `sha2_224` module,
* `256` enables SHA-2 256, accessible via the `sha2_256` module,
* `384` enables SHA-2 384, accessible via the `sha2_384` module,
* `512` enables SHA-2 512, accessible via the `sha2_512` module.

By default all of them are enabled.

To customize your setup, turn off the default features and enable only those that you want in your `Cargo.toml` file:

```toml
[dependencies]
chksum-sha2 = { version = "0.1.0", default-features = no, features = ["256", "512"] }
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-sha2 --no-default-features --features 256,512
```

## License

This crate is licensed under the MIT License.
