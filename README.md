![banner](assets/banner.png)

# Yobicrypto
[![Travis branch](https://img.shields.io/travis/yobicash/yobicrypto/master.svg)](https://travis-ci.org/yobicash/yobicrypto)
[![Coveralls github branch](https://img.shields.io/coveralls/github/yobicash/yobicrypto/master.svg)](https://coveralls.io/github/yobicash/yobicrypto?branch=master)
[![Crates.io](https://img.shields.io/crates/v/yobicrypto.svg)](https://crates.io/crates/yobicrypto)
[![Crates.io](https://img.shields.io/crates/l/yobicrypto.svg)]()
[![Docs.rs](https://docs.rs/yobicrypto/badge.svg)](https://docs.rs/yobicrypto)

Cryptographyc toolkit used in [Yobicash](https://yobicash.org).

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [License](#license)
- [Contributing](#contributing)

## Install

To install it add in your Cargo.toml:

```toml
# Cargo.toml

[dependencies]
yobicrypto = "^0.2"
```

and in the root of your crate:

```rust
//main.rs

extern crate yobicrypto;
```

## Usage

Look at the [documentation](https://docs.rs/yobicrypto) or at the tests for guidance.

```rust
// main.rs

use yobicrypto::{Random, Scalar, ZKPWitness, ZKPProof}; 

let instance = Scalar::random();
let witness = ZKPWitness::new(instance)?;
let message = Random::bytes(64);
let proof = ZKPProof::new(instance, &message)?;
let verified = proof.verify(witness)?;

assert!(verified);
```

## Maintainers

[@chritchens](https://github.com/chritchens)

## License

This project is license under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in yobicrypto by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
