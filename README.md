# dart-ASE 🚀🔒

[![Dart](https://img.shields.io/badge/Dart-3.6.1-blue.svg)](https://dart.dev/) [![License](https://img.shields.io/badge/License-GPL-green.svg)](LICENSE)

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

## 💻 Quickstart (with CLI)

1. **Clone & install**

    ```bash
    git clone https://github.com/RafaeloxMC/dart-ASE.git
    cd dart-ASE
    dart pub get
    ```

2. **Generate a key pair**

    ```bash
    dart run dart_ase gen
    # → pubkey.json & privkey.json
    ```

3. **Encrypt a message**

    ```bash
    dart run dart_ase enc pubkey.json "Hello, ASE is cool!"
    # → ciphertext.json
    ```

4. **Decrypt the message**

    ```bash
    dart run dart_ase dec privkey.json ciphertext.json
    # → prints: Hello, ASE is cool!
    ```

---

## 🖥 Quickstart (with Code)

Add the dependency to your `pubspec.yaml`:

```yaml
dependencies:
    dart_ase: ^1.1.0
```

Then use the library in your code:

```dart
import 'dart:convert';
import 'dart:io';
import 'package:dart_ase/src/hybrid/hybrid_pke.dart';
import 'package:dart_ase/src/io/serialize.dart';
import 'package:dart_ase/src/io/deserialize.dart';
import 'package:dart_ase/src/kem/kem.dart';
import 'package:dart_ase/src/kem/keypair.dart';

Future<void> main() async {
  // 1. Generate a new keypair
  final keyPair = keyGen();

  // 2. Encrypt a message using public key
  final message = "Hello, quantum-resistant encryption!";
  final encrypted = await encryptString(message, keyPair.pk);

  // 3. Decrypt the message using private key / secret key
  final decrypted = await decryptString(encrypted, keyPair.sk);
  print('Decrypted: $decrypted');

  // 4. Save keys and ciphertext to files (optional)
  File('pubkey.json').writeAsStringSync(serializePublicKey(keyPair.pk));
  File('ciphertext.json').writeAsStringSync(serializeCombinedCipher(encrypted));

  // 5. Load keys and ciphertext from files (optional)
  final loadedPk = deserializePublicKey('pubkey.json');
  final loadedCt = deserializeCombinedCipher('ciphertext.json');
}
```

### Core API Methods

-   **Key Generation**: `keyGen()`

    ```dart
    ASEKeyPair keyPair = keyGen();
    // keyPair.pk (public key)
    // keyPair.sk (secret key)
    ```

-   **Encryption**: `encryptString()`

    ```dart
    ASECombinedCipher cipher = await encryptString(plaintextString, publicKey);
    ```

-   **Decryption**: `decryptString()`

    ```dart
    String plaintext = await decryptString(ciphertext, privateKey);
    ```

-   **Serialization**: `serializePublicKey()`, `serializeCombinedCipher()`

    ```dart
    String jsonString = serializePublicKey(publicKey);
    String jsonString = serializeCombinedCipher(ciphertext);
    ```

-   **Deserialization**: `deserializePublicKey()`, `deserializeCombinedCipher()`

    ```dart
    // From file:
    ASEPublicKey publicKey = deserializePublicKey('path/to/pubkey.json');
    ASECombinedCipher cipher = deserializeCombinedCipher('path/to/cipher.json');

    // From json string:
    String jsonString = '{"kemCt":{"u":[[...]],"v":[...]},"nonce":[...],"ciphertext":[...],"salt":[...]}';
    ASECombinedCipher cipherFromString = deserializeCombinedCipherFromString(jsonString);

    // From parsed json object:
    Map<String, dynamic> jsonObject = jsonDecode(jsonString);
    ASECombinedCipher cipherFromJson = deserializeCombinedCipherFromJson(jsonObject);
    ```

---

## 🔍 How It Works

1. **KEM KeyGen**

    - Generate public matrix $A\in R_q^{k\times k}$ and secret vector $\mathbf{s}\in R_q^k$.
    - Compute $\mathbf{b} = A\mathbf{s} + \mathbf{e}$ with small error $\mathbf{e}$.

2. **KEM Encapsulation**

    - Sample ephemeral $\mathbf{r}\in R_q^k$ and noise $\mathbf{e}_1,\mathbf{e}_2$.
    - Compute $\mathbf{u} = A^T\mathbf{r} + \mathbf{e}_1$ and encode message bits into $\mathbf{v}$.

3. **Shared Secret**

    - Decapsulation recovers $\mathbf{r}$ from $\mathbf{u},\mathbf{v}$.
    - Derive a symmetric key via HKDF‑SHA256:

        $$\mathrm{AES\_Key} = \mathrm{HKDF}(\mathbf{r})$$

4. **AES‑GCM AEAD**

    - Encrypt arbitrary plaintext under the derived 256‑bit key.
    - Outputs AEAD ciphertext + 128‑bit MAC.

---

## ⚠️ Security Disclaimer

> **This library is (probably) _not_ production‑safe.**
> No security experts or cryptographers have reviewed or audited this implementation.
> Use this code for learning and experimentation only — **never** for real-world confidentiality.

---

## 🤝 Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/XYZ`)
3. Commit your changes (`git commit -m "Add XYZ"`)
4. Push to the branch (`git push origin feature/XYZ`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the [GNU General Public License v3](LICENSE).

---
