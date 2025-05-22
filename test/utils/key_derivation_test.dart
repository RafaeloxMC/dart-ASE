import 'dart:typed_data';
import 'package:dart_ase/utils/hkdf_aes.dart';
import 'package:test/test.dart';

void main() {
  group('AES key derivation', () {
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
      final inputBytes = Uint8List.fromList(List.generate(256, (i) => i % 2));

      final key1 = await deriveAesKey(inputBytes);
      final key2 = await deriveAesKey(inputBytes);

      expect(key1, isNot(equals(key2)));
      expect(key1.length, equals(32));
    });

    test('deriveAesKey produces different output for different input',
        () async {
      final input1 = Uint8List.fromList(List.generate(256, (i) => 0));
      final input2 = Uint8List.fromList(List.generate(256, (i) => 1));

      final key1 = await deriveAesKey(input1);
      final key2 = await deriveAesKey(input2);

      expect(key1, isNot(equals(key2)));
    });

    test('deriveAesKey produces consistent output with same salt', () async {
      final inputBytes = Uint8List.fromList(List.generate(256, (i) => i % 2));
      final testSalt = Uint8List.fromList(List.generate(32, (i) => i));

      final key1 = await deriveAesKeyWithSalt(inputBytes, testSalt);
      final key2 = await deriveAesKeyWithSalt(inputBytes, testSalt);

      expect(key1, equals(key2));
      expect(key1.length, equals(32));
    });

    test(
        'deriveAesKeyWithSalt produces different output for different input with same salt',
        () async {
      final input1 = Uint8List.fromList(List.generate(256, (i) => 0));
      final input2 = Uint8List.fromList(List.generate(256, (i) => 1));
      final testSalt = Uint8List.fromList(List.generate(32, (i) => i));

      final key1 = await deriveAesKeyWithSalt(input1, testSalt);
      final key2 = await deriveAesKeyWithSalt(input2, testSalt);

      expect(key1, isNot(equals(key2)));
    });
  });
}
