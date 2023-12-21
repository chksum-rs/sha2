//! This crate provides an implementation of SHA-2 hash functions with a straightforward interface for computing digests of bytes, files, directories, and more.
//!
//! For a low-level interface, you can explore the [`chksum_hash_sha2`] crate.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2 = "0.0.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-sha2
//! ```     
//!
//! # Usage
//!
//! Use the [`chksum`] function to calcualate digest of file, directory and so on.
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_256::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Input Types
//!
//! ## Bytes
//!
//! ### Array
//!
//! ```rust
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = [0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Vec
//!
//! ```rust
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = vec![0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Slice
//!
//! ```rust
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = &[0, 1, 2, 3];
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Strings
//!
//! ### str
//!
//! ```rust
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = "&str";
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### String
//!
//! ```rust
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let data = String::from("String");
//! let digest = sha2_256::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## File
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_256::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Directory
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::read_dir;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let readdir = read_dir(path)?;
//! let digest = sha2_256::chksum(readdir)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Path
//!
//! ```rust
//! # use std::path::Path;
//! use std::path::PathBuf;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let path = PathBuf::from(path);
//! let digest = sha2_256::chksum(path)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Standard Input
//!
//! ```rust
//! use std::io::stdin;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper() -> Result<()> {
//! let stdin = stdin();
//! let digest = sha2_256::chksum(stdin)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Algorithms
//!
//! ## SHA-2 224
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_224::Result;
//! use chksum_sha2::sha2_224;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_224::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "90382cbfda2656313ad61fd74b32ddfa4bcc118f660bd4fba9228ced"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## SHA-2 256
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_256::Result;
//! use chksum_sha2::sha2_256;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_256::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "44752f37272e944fd2c913a35342eaccdd1aaf189bae50676b301ab213fc5061"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## SHA-2 384
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_384::Result;
//! use chksum_sha2::sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_384::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## SHA-2 512
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2::sha2_512::Result;
//! use chksum_sha2::sha2_512;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_512::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "ed59c5759a9ece516cec0c0623142d0e9fe70a27d750eee7fd38f4550d50addd873d0fa1a51fc823c1e3d5cada203f4a05d8325caacb7d3e0727a701f3f07e5f"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! ## Algorithms
//!
//! Cargo features are utilized to enable or disable specific SHA-2 algorithm variants.
//!
//! * `224` enables SHA-2 224, accessible via the [`sha2_224`] module.
//! * `256` enables SHA-2 256, accessible via the [`sha2_256`] module.
//! * `384` enables SHA-2 384, accessible via the [`sha2_384`] module.
//! * `512` enables SHA-2 512, accessible via the [`sha2_512`] module.
//!
//! By default, all of these features are enabled.
//!
//! To customize your setup, disable the default features and enable only those that you need in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2 = { version = "0.0.0", default-features = false, features = ["256", "512"] }
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2 --no-default-features --features 256,512
//! ```
//!
//! ## Extra Options
//!
//! Cargo features are also utilized to enable extra options.
//!
//! * `reader` enables the `reader` module with the `Reader` struct within each variant module.
//! * `writer` enables the `writer` module with the `Writer` struct within each variant module.
//!
//! By default, neither of these features is enabled.
//!
//! To customize your setup, disable the default features and enable only those that you need in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2 = { version = "0.0.0", features = ["reader", "writer"] }
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2 --features reader,writer
//! ```
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

#[doc(no_inline)]
pub use chksum_core::{chksum, Digest, Error, Hash, Result};
#[doc(no_inline)]
pub use chksum_hash_sha2 as hash;
#[cfg(feature = "224")]
#[doc(no_inline)]
pub use chksum_sha2_224 as sha2_224;
#[cfg(feature = "224")]
#[doc(no_inline)]
pub use chksum_sha2_224::SHA2_224;
#[cfg(feature = "256")]
#[doc(no_inline)]
pub use chksum_sha2_256 as sha2_256;
#[cfg(feature = "256")]
#[doc(no_inline)]
pub use chksum_sha2_256::SHA2_256;
#[cfg(feature = "384")]
#[doc(no_inline)]
pub use chksum_sha2_384 as sha2_384;
#[cfg(feature = "384")]
#[doc(no_inline)]
pub use chksum_sha2_384::SHA2_384;
#[cfg(feature = "512")]
#[doc(no_inline)]
pub use chksum_sha2_512 as sha2_512;
#[cfg(feature = "512")]
#[doc(no_inline)]
pub use chksum_sha2_512::SHA2_512;
