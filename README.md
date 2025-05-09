# dart-ASE 🚀🔒

[![Dart](https://img.shields.io/badge/Dart-2.19-blue.svg)](https://dart.dev/) [![License](https://img.shields.io/badge/License-GPL-green.svg)](LICENSE)

## Actually Secure Encryption (ASE)

**dart-ASE** is a proof‑of‑concept library implementing a hybrid lattice‑based KEM + AES‑GCM scheme in pure Dart.

> **Warning:** This code has _never_ been audited by professional cryptographers or security experts. **Not recommended** for use in production or for securing real data!

---

## 🚀 Features

-   **Post‑Quantum KEM**

    -   Ring‑learning‑with‑errors based key encapsulation
    -   Modular arithmetic over \(q = 3329\), polynomial degree \(n = 256\)
    -   Noise sampling parameter \(eta = 1\)

-   **Hybrid AEAD**

    -   Derives a 256‑bit AES‑GCM key via HKDF(SHA‑256) from the KEM shared secret
    -   Authenticated encryption with 96‑bit nonce, 128‑bit tag

-   **Pure Dart**

    -   No native extensions
    -   Zero‑dependency aside from [cryptography](https://pub.dev/packages/cryptography)

-   **CLI Tools**
    -   `gen`: generate keypair (pubkey.json & privkey.json)
    -   `enc`: encrypt plaintext → ciphertext.json
    -   `dec`: decrypt ciphertext.json → prints your message

---

## 💻 Quickstart

1. **Clone & install**

    ```bash
    git clone https://github.com/RafaeloxMC/dart-ASE.git
    cd dart-ASE
    dart pub get
    ```

2. **CLI Usage**
    ```bash
    dart run main.dart gen # -> pubkey.json & privkey.json
    dart run main.dart enc pubkey.json "Hello World" # -> ciphertext.json
    dart run main.dart dec privkey.json ciphertext.json # -> Hello World
    ```
