import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';

/// This class represents the public key for the ASE KEM scheme.
/// It contains a list of polynomial vectors A and a polynomial b.
class ASEPublicKey {
  final List<PolyVec> A;
  final PolyVec b;
  ASEPublicKey(this.A, this.b);
}

/// This class represents the private key for the ASE KEM scheme.
/// It contains a polynomial vector s.
class ASEPrivateKey {
  final PolyVec s;
  ASEPrivateKey(this.s);
}

/// This class represents the key pair for the ASE KEM scheme.
/// It contains a public key and a private key.
class ASEKeyPair {
  final ASEPublicKey pk;
  final ASEPrivateKey sk;
  ASEKeyPair(this.pk, this.sk);
}

/// This class represents the ciphertext for the ASE KEM scheme.
/// It contains a polynomial vector u and a polynomial v.
class ASECiphertextKEM {
  final PolyVec u;
  final Poly v;
  ASECiphertextKEM(this.u, this.v);
}
