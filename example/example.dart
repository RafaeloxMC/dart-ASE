// ignore_for_file: unused_local_variable

import 'dart:io';
import 'dart:convert';
import 'package:dart_ase/src/hybrid/hybrid_pke.dart';
import 'package:dart_ase/src/io/deserialize.dart';
import 'package:dart_ase/src/io/serialize.dart';
import 'package:dart_ase/src/kem/kem.dart';
import 'package:dart_ase/src/kem/keypair.dart';
import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';

Future<void> main() async {
  print('=== Dart ASE Example ===');

  // Generate a new keypair
  print('\n1. Generating keypair...');
  final keyPair = keyGen();
  print('   ✓ Keypair generated');

  // Encrypt a message
  final message = "Hello, quantum-resistant encryption!";
  print('\n2. Encrypting message: "$message"');
  final encrypted = await encryptString(message, keyPair.pk);
  print('   ✓ Message encrypted (${encrypted.ciphertext.length} bytes)');

  // Decrypt the message
  print('\n3. Decrypting message...');
  final decrypted = await decryptString(encrypted, keyPair.sk);
  print('   ✓ Decrypted: "$decrypted"');

  // Save keys and ciphertext to files
  print('\n4. Saving keys and ciphertext to files...');
  File('example_pubkey.json').writeAsStringSync(serializePublicKey(keyPair.pk));
  File('example_privkey.json').writeAsStringSync(
      jsonEncode({'s': keyPair.sk.s.vec.map((p) => p.coeffs).toList()}));
  File('example_ciphertext.json')
      .writeAsStringSync(serializeCombinedCipher(encrypted));
  print('   ✓ Files saved');

  // Load keys and ciphertext from files
  print('\n5. Loading keys and ciphertext from files...');
  final loadedPk = deserializePublicKey('example_pubkey.json');
  final loadedPrivJson =
      jsonDecode(File('example_privkey.json').readAsStringSync());
  final loadedSk = ASEPrivateKey(PolyVec((loadedPrivJson['s'] as List)
      .map((c) => Poly(List<int>.from(c)))
      .toList()));
  final loadedCt = deserializeCombinedCipher('example_ciphertext.json');
  print('   ✓ Files loaded');

  // Verify decryption with loaded keys
  print('\n6. Verifying decryption with loaded keys...');
  final verifiedMsg = await decryptString(loadedCt, loadedSk);
  print('   ✓ Verified: "$verifiedMsg"');

  // Clean up example files
  print('\n7. Cleaning up example files...');
  File('example_pubkey.json').deleteSync();
  File('example_privkey.json').deleteSync();
  File('example_ciphertext.json').deleteSync();
  print('   ✓ Files deleted');

  print('\nExample completed successfully!');
}
