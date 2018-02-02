# Yobicrypto

![banner](assets/banner.png)

Cryptographyc toolkit used in [Yobicash](https://yobicash.org).

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [License](#license)
- [Contributing](#contributing)

## Install

Yobicrypto depends on unstable features, so use is only on nightly projects.
To install it add in your Cargo.toml:

```toml
# Cargo.toml

[dependencies]
yobicrypto = { git = "https://github.com/yobicash/yobicrypto", version = "^0.1" }
```

and in the root of your crate:

```rust
//main.rs

extern crate yobicrypto;
```

## Usage

Look at the documentation or at the tests for guidance.

```rust
// main.rs

use yobicrypto::{Random, Scalar, ZKPWitness, ZKPProof}; 

let instance = Scalar::random();
let witness = ZKPWitness::new(instance);
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

Pull requests are well accepted. By askying to contribute you implicitly accept the above [licenses](#license).
