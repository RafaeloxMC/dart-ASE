import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_ase/src/constants.dart';
import 'package:dart_ase/src/hybrid/hybrid_pke.dart';
import 'package:dart_ase/src/io/path.dart';
import 'package:dart_ase/src/kem/keypair.dart';
import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';

/// Deserializes the public key from a JSON file
/// The file should contain a JSON object with the keys 'A' and 'b'.
ASEPublicKey deserializePublicKey(String path) {
  if (!isPathSafe(path)) {
    throw ArgumentError('Unsafe file path');
  }

  final file = File(path);
  if (!file.existsSync()) {
    throw FileSystemException('File not found', path);
  }

  if (file.lengthSync() > 1024 * 1024) {
    throw FileSystemException('File too large', path);
  }

  var m = jsonDecode(file.readAsStringSync());
  var A = (m['A'] as List)
      .map((pv) => PolyVec(
          (pv as List).map((c) => Poly(List<int>.from(c as List))).toList()))
      .toList();
  var bVec =
      (m['b'] as List).map((c) => Poly(List<int>.from(c as List))).toList();
  return ASEPublicKey(A, PolyVec(bVec));
}

/// Deserializes the combined ciphertext from a JSON file
/// The file should contain a JSON object with the keys 'kemCt', 'nonce', 'ciphertext', and 'salt'.
ASECombinedCipher deserializeCombinedCipher(String path) {
  if (!isPathSafe(path)) {
    throw ArgumentError('Unsafe file path');
  }

  final file = File(path);
  if (!file.existsSync()) {
    throw FileSystemException('File not found', path);
  }

  if (file.lengthSync() > 1024 * 1024) {
    throw FileSystemException('File too large', path);
  }

  return deserializeCombinedCipherFromString(file.readAsStringSync());
}

/// Deserializes the combined ciphertext from a JSON string
/// The string should contain a JSON object with the keys 'kemCt', 'nonce', 'ciphertext', and 'salt'.
ASECombinedCipher deserializeCombinedCipherFromString(String jsonString) {
  var m = jsonDecode(jsonString) as Map<String, dynamic>;
  if (!m.containsKey('kemCt') ||
      !m.containsKey('nonce') ||
      !m.containsKey('ciphertext') ||
      !m.containsKey('salt')) {
    throw FormatException('Invalid ciphertext format');
  }
  return deserializeCombinedCipherFromJson(m);
}

/// Deserializes the combined ciphertext from a parsed JSON object
/// The object should contain the keys 'kemCt', 'nonce', 'ciphertext', and 'salt'.
ASECombinedCipher deserializeCombinedCipherFromJson(Map<String, dynamic> m) {
  if (!m.containsKey('kemCt') ||
      !m.containsKey('nonce') ||
      !m.containsKey('ciphertext') ||
      !m.containsKey('salt')) {
    throw FormatException('Invalid ciphertext format');
  }

  var kem = m['kemCt'] as Map;
  if (!kem.containsKey('u') || !kem.containsKey('v')) {
    throw FormatException('Invalid KEM ciphertext format');
  }

  var uList = kem['u'] as List;
  if (uList.length != k) {
    throw FormatException('Invalid KEM ciphertext dimension');
  }

  var polys = uList.map((elem) => Poly(List<int>.from(elem as List))).toList();
  var uVec = PolyVec(polys);
  var v = Poly(List<int>.from(kem['v'] as List));
  var nonce = Uint8List.fromList(List<int>.from(m['nonce'] as List));
  var sym = Uint8List.fromList(List<int>.from(m['ciphertext'] as List));
  var salt = Uint8List.fromList(List<int>.from(m['salt'] as List));
  if (nonce.length != 12) throw FormatException('Invalid nonce length');
  if (sym.length < 16) throw FormatException('Invalid ciphertext length');

  return ASECombinedCipher(
      ASECiphertextKEM(uVec, v), nonce, sym, Uint8List(0), salt);
}
