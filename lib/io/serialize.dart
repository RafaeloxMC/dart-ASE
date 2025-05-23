import 'dart:convert';

import 'package:dart_ase/hybrid/hybrid_pke.dart';
import 'package:dart_ase/kem/keypair.dart';

/// Serializes the public key to JSON format
String serializePublicKey(ASEPublicKey pk) => jsonEncode({
      'A': pk.A.map((pv) => pv.vec.map((p) => p.coeffs).toList()).toList(),
      'b': pk.b.vec.map((p) => p.coeffs).toList(),
    });

/// Serializes the private key to JSON format
String serializePrivateKey(ASEPrivateKey sk) => jsonEncode({
      's': sk.s.vec.map((p) => p.coeffs).toList(),
    });

/// Deserializes the public key from JSON format
String serializeCombinedCipher(ASECombinedCipher cc) => jsonEncode({
      'kemCt': {
        'u': cc.kemCt.u.vec.map((p) => p.coeffs).toList(),
        'v': cc.kemCt.v.coeffs,
      },
      'nonce': cc.nonce.toList(),
      'ciphertext': cc.ciphertext.toList(),
      'salt': cc.salt.toList(),
    });
