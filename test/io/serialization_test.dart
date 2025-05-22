import 'dart:io';
import 'dart:typed_data';
import 'dart:math' as math;
import 'package:dart_ase/constants.dart';
import 'package:dart_ase/hybrid/hybrid_pke.dart';
import 'package:dart_ase/io/deserialize.dart';
import 'package:dart_ase/io/serialize.dart';
import 'package:dart_ase/kem/kem.dart';
import 'package:dart_ase/poly/polynominal.dart';
import 'package:dart_ase/poly/polyvec.dart';
import 'package:test/test.dart';

void main() {
  final rnd = math.Random.secure();

  group('Serialization', () {
    test('Public key serialization/deserialization', () {
      final kp = keyGen();
      final serialized = serializePublicKey(kp.pk);

      final tempFile = File('temp_pubkey.json');
      tempFile.writeAsStringSync(serialized);

      final deserialized = deserializePublicKey('temp_pubkey.json');
      tempFile.deleteSync();

      expect(deserialized.A.length, equals(k));
      expect(deserialized.A[0].vec.length, equals(k));
      expect(deserialized.b.vec.length, equals(k));
    });

    test('CombinedCipher serialization/deserialization', () {
      final kp = keyGen();
      final r = PolyVec(List.generate(
          k, (_) => Poly(List.generate(n, (_) => rnd.nextInt(2)))));
      final kemCt = kemEncap(kp.pk, r);

      final cc = ASECombinedCipher(
        kemCt,
        Uint8List.fromList(List.filled(12, 1)), // nonce
        Uint8List.fromList(List.filled(32, 2)), // ciphertext
        Uint8List(0), // aad
        Uint8List.fromList(List.filled(16, 3)), // salt
      );

      final serialized = serializeCombinedCipher(cc);

      final tempFile = File('temp_cipher.json');
      tempFile.writeAsStringSync(serialized);

      final deserialized = deserializeCombinedCipher('temp_cipher.json');
      tempFile.deleteSync();

      expect(deserialized.nonce.length, equals(cc.nonce.length));
      expect(deserialized.ciphertext.length, equals(cc.ciphertext.length));
    });

    test('Public key serialization from string', () {
      final kp = keyGen();
      final serialized = serializePublicKey(kp.pk);

      final deserialized = deserializePublicKeyFromString(serialized);

      expect(deserialized.A.length, equals(k));
      expect(deserialized.A[0].vec.length, equals(k));
    });

    test('Private key serialization', () {
      final kp = keyGen();
      final serialized = serializePrivateKey(kp.sk);

      expect(serialized.contains('"s":'), isTrue);

      final deserialized = deserializePrivateKeyFromString(serialized);
      expect(deserialized.s.vec.length, equals(k));
    });

    test('Combined cipher serialization from string', () {
      final kp = keyGen();
      final r = PolyVec(List.generate(
          k, (_) => Poly(List.generate(n, (_) => rnd.nextInt(2)))));
      final kemCt = kemEncap(kp.pk, r);

      final cc = ASECombinedCipher(
        kemCt,
        Uint8List.fromList(List.filled(12, 1)), // nonce
        Uint8List.fromList(List.filled(32, 2)), // ciphertext
        Uint8List(0), // aad
        Uint8List.fromList(List.filled(16, 3)), // salt
      );

      final serialized = serializeCombinedCipher(cc);
      final deserialized = deserializeCombinedCipherFromString(serialized);

      expect(deserialized.nonce.length, equals(cc.nonce.length));
      expect(deserialized.ciphertext.length, equals(cc.ciphertext.length));
    });

    test('Combined cipher serialization with invalid format', () {
      final invalidJson = '{"invalid": "format"}';
      expect(() => deserializeCombinedCipherFromString(invalidJson),
          throwsA(isA<FormatException>()));
    });
  });
}
