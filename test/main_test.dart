import 'dart:developer';
import 'dart:io';
import 'dart:typed_data';
import 'package:dart_ase/src/constants.dart';
import 'package:dart_ase/src/hybrid/hybrid_pke.dart';
import 'package:dart_ase/src/io/deserialize.dart';
import 'package:dart_ase/src/io/serialize.dart';
import 'package:dart_ase/src/kem/kem.dart';
import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';
import 'package:dart_ase/src/utils/hkdf_aes.dart';
import 'package:test/test.dart';
import 'dart:math' as math;

var _rnd = math.Random.secure();

void main() {
  group('Polynomial operations', () {
    log('Starting polynomial operation tests');

    test('Polynomial addition', () {
      log('Creating polynomials for addition test');
      final p1 = Poly([1, 2, 3, 4, ...List.filled(n - 4, 0)]);
      final p2 = Poly([5, 6, 7, 8, ...List.filled(n - 4, 0)]);

      log('Adding polynomials');
      final sum = p1 + p2;
      log('First few coefficients: ${sum.coeffs.sublist(0, 4)}');

      expect(sum.coeffs.sublist(0, 4), equals([6, 8, 10, 12]));
      expect(sum.coeffs.length, equals(n));
    });

    test('Polynomial subtraction', () {
      log('Creating polynomials for subtraction test');
      final p1 = Poly([10, 20, 30, 40, ...List.filled(n - 4, 0)]);
      final p2 = Poly([5, 5, 10, 20, ...List.filled(n - 4, 0)]);

      log('Subtracting polynomials');
      final diff = p1 - p2;
      log('First few coefficients: ${diff.coeffs.sublist(0, 4)}');

      expect(diff.coeffs.sublist(0, 4), equals([5, 15, 20, 20]));
      expect(diff.coeffs.length, equals(n));
    });

    test('Polynomial multiplication', () {
      log('Creating polynomials for multiplication test');
      final p1 = Poly([1, 1, 0, 0, ...List.filled(n - 4, 0)]);
      final p2 = Poly([1, 1, 0, 0, ...List.filled(n - 4, 0)]);

      log('Multiplying polynomials');
      final product = Poly.polymul(p1, p2);
      log('First few coefficients: ${product.coeffs.sublist(0, 4)}');

      expect(product.coeffs[0], equals(1));
      expect(product.coeffs[1], equals(2));
      expect(product.coeffs[2], equals(1));
    });

    test('Random polynomial generation', () {
      log('Generating random uniform polynomial');
      final p = Poly.randomUniform();
      log('Polynomial generated with ${p.coeffs.length} coefficients');
      log('First few coefficients: ${p.coeffs.sublist(0, 5)}');

      expect(p.coeffs.length, equals(n));
      for (final coeff in p.coeffs) {
        expect(coeff >= 0 && coeff < q, isTrue);
      }
      log('All coefficients are within range [0, q-1]');
    });

    test('Noise sampling', () {
      log('Sampling noise polynomial with eta = $eta');
      final p = Poly.sampleNoise();
      log('Noise polynomial generated with ${p.coeffs.length} coefficients');
      log('First few coefficients: ${p.coeffs.sublist(0, 10)}');

      expect(p.coeffs.length, equals(n));

      bool allInRange = true;
      for (int i = 0; i < p.coeffs.length; i++) {
        final coeff = p.coeffs[i];
        if (coeff < -eta || coeff > eta) {
          log('Out-of-range coefficient at index $i: $coeff (should be in [-$eta, $eta])');
          allInRange = false;
        }
      }
      expect(allInRange, isTrue,
          reason: 'All coefficients should be in range [-$eta, $eta]');

      for (final coeff in p.coeffs) {
        expect(coeff >= -eta && coeff <= eta, isTrue);
      }
      log('All noise coefficients are within range [-$eta, $eta]');
    });
  });

  group('PolyVec operations', () {
    log('Starting polynomial vector operation tests');

    test('PolyVec initialization', () {
      log('Initializing empty polynomial vector');
      final pv = PolyVec();
      log('PolyVec created with ${pv.vec.length} polynomials');

      expect(pv.vec.length, equals(k));
      for (final poly in pv.vec) {
        expect(poly.coeffs.length, equals(n));
      }
      log('All polynomials have correct length');
    });

    test('PolyVec addition', () {
      log('Creating polynomial vectors for addition test');
      final pv1 = PolyVec([
        Poly([1, 2, ...List.filled(n - 2, 0)]),
        Poly([3, 4, ...List.filled(n - 2, 0)]),
        Poly([5, 6, ...List.filled(n - 2, 0)])
      ]);

      final pv2 = PolyVec([
        Poly([10, 20, ...List.filled(n - 2, 0)]),
        Poly([30, 40, ...List.filled(n - 2, 0)]),
        Poly([50, 60, ...List.filled(n - 2, 0)])
      ]);

      log('Adding polynomial vectors');
      final sum = pv1 + pv2;
      log('First coefficients: [${sum.vec[0].coeffs[0]}, ${sum.vec[1].coeffs[0]}, ${sum.vec[2].coeffs[0]}]');

      expect(sum.vec[0].coeffs[0], equals(11));
      expect(sum.vec[1].coeffs[0], equals(33));
      expect(sum.vec[2].coeffs[0], equals(55));
    });

    test('Matrix multiplication', () {
      log('Creating matrix and vector for multiplication test');
      final A = List<PolyVec>.generate(
          k,
          (i) => PolyVec(List.generate(
              k, (j) => Poly([i + j + 1, ...List.filled(n - 1, 0)]))));

      final s =
          PolyVec(List.generate(k, (i) => Poly([1, ...List.filled(n - 1, 0)])));
      log('Matrix A has dimensions ${A.length}×${A[0].vec.length}');

      log('Performing matrix multiplication');
      final result = PolyVec.mulMatrix(A, s);
      log('Result has ${result.vec.length} polynomials');

      expect(result.vec.length, equals(k));
    });
  });

  group('Key generation and KEM', () {
    log('Starting key generation and KEM tests');

    test('keyGen produces valid keypair', () {
      log('Generating keypair');
      final kp = keyGen();
      log('Keypair generated');
      log('Public key: A matrix size=${kp.pk.A.length}×${kp.pk.A[0].vec.length}, b vector size=${kp.pk.b.vec.length}');
      log('Private key: s vector size=${kp.sk.s.vec.length}');

      expect(kp.pk.A.length, equals(k));
      expect(kp.pk.b.vec.length, equals(k));
      expect(kp.sk.s.vec.length, equals(k));
    });

    test('KEM encapsulation and decapsulation', () {
      log('Generating keypair for KEM test');
      final kp = keyGen();

      log('Creating random message vector');
      final r = PolyVec(List.generate(
          k, (_) => Poly(List.generate(n, (_) => _rnd.nextInt(2)))));

      log('Performing KEM encapsulation');
      final ct = kemEncap(kp.pk, r);
      log('Ciphertext generated: u vector size=${ct.u.vec.length}');

      expect(ct.u.vec.length, equals(k));

      log('Performing KEM decapsulation');
      final recovered = kemDecap(ct, kp.sk);
      log('Decapsulation complete');

      int matchingBits = 0;
      for (int i = 0; i < n; i++) {
        if (recovered.vec[0].coeffs[i] == r.vec[0].coeffs[i]) {
          matchingBits++;
        }
      }

      final recoveryRate = matchingBits / n;
      log('Recovery rate: ${(recoveryRate * 100).toStringAsFixed(2)}% (${matchingBits}/${n} bits)');

      expect(recoveryRate > 0.9, isTrue);
    });
  });

  group('Serialization', () {
    log('Starting serialization tests');

    test('Public key serialization/deserialization', () {
      log('Generating keypair');
      final kp = keyGen();

      log('Serializing public key');
      final serialized = serializePublicKey(kp.pk);
      log('Public key JSON size: ${serialized.length} characters');

      log('Writing public key to temporary file');
      final tempFile = File('temp_pubkey.json');
      tempFile.writeAsStringSync(serialized);

      log('Deserializing public key from file');
      final deserialized = deserializePublicKey('temp_pubkey.json');
      log('Public key deserialized');

      log('Cleaning up temporary file');
      tempFile.deleteSync();

      expect(deserialized.A.length, equals(k));
      expect(deserialized.A[0].vec.length, equals(k));
      expect(deserialized.b.vec.length, equals(k));
      log('Deserialized public key structure verified');
    });

    test('CombinedCipher serialization/deserialization', () {
      log('Preparing combined cipher for serialization test');
      final kp = keyGen();
      final r = PolyVec(List.generate(
          k, (_) => Poly(List.generate(n, (_) => _rnd.nextInt(2)))));
      log('Generating KEM ciphertext');
      final kemCt = kemEncap(kp.pk, r);

      log('Creating combined cipher with KEM and symmetric components');
      final cc = ASECombinedCipher(
        kemCt,
        Uint8List.fromList(List.filled(12, 1)), // nonce
        Uint8List.fromList(List.filled(32, 2)), // ciphertext
        Uint8List(0), // aad
        Uint8List.fromList(List.filled(16, 3)), // salt
      );

      log('Serializing combined cipher');
      final serialized = serializeCombinedCipher(cc);
      log('Combined cipher JSON size: ${serialized.length} characters');

      log('Writing cipher to temporary file');
      final tempFile = File('temp_cipher.json');
      tempFile.writeAsStringSync(serialized);

      log('Deserializing combined cipher from file');
      final deserialized = deserializeCombinedCipher('temp_cipher.json');
      log('Combined cipher deserialized');

      log('Cleaning up temporary file');
      tempFile.deleteSync();

      expect(deserialized.nonce.length, equals(cc.nonce.length));
      expect(deserialized.ciphertext.length, equals(cc.ciphertext.length));
      log('Deserialized cipher structure verified');
    });
  });

  group('End-to-end encryption', () {
    log('Starting end-to-end encryption tests');

    test('Encrypt and decrypt a message', () async {
      log('Generating keypair for encryption test');
      final kp = keyGen();
      final message = "Hello, Quantum-Resistant Encryption!";
      log('Test message: "$message"');

      log('Encrypting message');
      final encrypted = await encryptString(message, kp.pk);
      log('Message encrypted, ciphertext length: ${encrypted.ciphertext.length} bytes');
      expect(encrypted.ciphertext.isNotEmpty, isTrue);

      log('Decrypting message');
      final decrypted = await decryptString(encrypted, kp.sk);
      log('Message decrypted: "$decrypted"');

      expect(decrypted, equals(message));
      log('Decryption successful, message matches original');
    });

    test('Encryption with different keys fails authentication', () async {
      log('Generating two different keypairs');
      final kp1 = keyGen();
      final kp2 = keyGen();
      final message = "This shouldn't decrypt properly";
      log('Test message: "$message"');

      log('Encrypting message with first public key');
      final encrypted = await encryptString(message, kp1.pk);
      log('Message encrypted, attempting decryption with wrong key');

      expect(() async {
        log('Attempting decryption with incorrect private key');
        await decryptString(encrypted, kp2.sk);
      }, throwsA(isA<StateError>()));
      log('Decryption correctly failed with authentication error');
    });
  });

  group('AES key derivation', () {
    log('Starting AES key derivation tests');

    test(
        'deriveAesKeyWithSalt produces consistent output for same input and salt',
        () async {
      final inputBytes = Uint8List.fromList(List.generate(256, (i) => i % 2));
      final testSalt = Uint8List.fromList(List.generate(32, (i) => i));

      final key1 = await deriveAesKeyWithSalt(inputBytes, testSalt);
      final key2 = await deriveAesKeyWithSalt(inputBytes, testSalt);

      expect(key1, equals(key2));
      expect(key1.length, equals(32));
    });

    test('deriveAesKey produces different results for each call', () async {
      log('Creating test input bytes');
      final inputBytes = Uint8List.fromList(List.generate(256, (i) => i % 2));

      log('Deriving first key');
      final key1 = await deriveAesKey(inputBytes);
      log('Deriving second key from same input');
      final key2 = await deriveAesKey(inputBytes);
      log('Keys derived, key length: ${key1.length} bytes');

      expect(key1, isNot(equals(key2)));
      expect(key1.length, equals(32));
      log('Keys differ as expected due to random salt and have correct length (256 bits)');
    });

    test('deriveAesKey produces different output for different input',
        () async {
      log('Creating two different test inputs');
      final input1 = Uint8List.fromList(List.generate(256, (i) => 0));
      final input2 = Uint8List.fromList(List.generate(256, (i) => 1));

      log('Deriving key from first input');
      final key1 = await deriveAesKey(input1);
      log('Deriving key from second input');
      final key2 = await deriveAesKey(input2);

      expect(key1, isNot(equals(key2)));
      log('Keys are different as expected');
    });

    test('deriveAesKey produces consistent output with same salt', () async {
      log('Creating test input bytes and fixed salt');
      final inputBytes = Uint8List.fromList(List.generate(256, (i) => i % 2));
      final testSalt = Uint8List.fromList(List.generate(32, (i) => i));

      log('Deriving first key with fixed salt');
      final key1 = await deriveAesKeyWithSalt(inputBytes, testSalt);
      log('Deriving second key with same input and same salt');
      final key2 = await deriveAesKeyWithSalt(inputBytes, testSalt);
      log('Keys derived, key length: ${key1.length} bytes');

      expect(key1, equals(key2));
      expect(key1.length, equals(32));
      log('Keys match and have correct length (256 bits)');
    });

    test(
        'deriveAesKeyWithSalt produces different output for different input with same salt',
        () async {
      log('Creating two different test inputs and a fixed salt');
      final input1 = Uint8List.fromList(List.generate(256, (i) => 0));
      final input2 = Uint8List.fromList(List.generate(256, (i) => 1));
      final testSalt = Uint8List.fromList(List.generate(32, (i) => i));

      log('Deriving key from first input');
      final key1 = await deriveAesKeyWithSalt(input1, testSalt);
      log('Deriving key from second input');
      final key2 = await deriveAesKeyWithSalt(input2, testSalt);

      expect(key1, isNot(equals(key2)));
      log('Keys are different as expected');
    });
  });
}
