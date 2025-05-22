import 'package:dart_ase/hybrid/hybrid_pke.dart';
import 'package:dart_ase/kem/kem.dart';
import 'package:test/test.dart';

void main() {
  group('End-to-end encryption', () {
    test('Encrypt and decrypt a message', () async {
      final kp = keyGen();
      final message = "Hello, Quantum-Resistant Encryption!";

      final encrypted = await encryptString(message, kp.pk);
      expect(encrypted.ciphertext.isNotEmpty, isTrue);

      final decrypted = await decryptString(encrypted, kp.sk);
      expect(decrypted, equals(message));
    });

    test('Encryption with different keys fails authentication', () async {
      final kp1 = keyGen();
      final kp2 = keyGen();
      final message = "This shouldn't decrypt properly";

      final encrypted = await encryptString(message, kp1.pk);

      expect(() async {
        await decryptString(encrypted, kp2.sk);
      }, throwsA(isA<StateError>()));
    });

    test('Encrypt and decrypt empty message', () async {
      final kp = keyGen();
      final message = "";

      final encrypted = await encryptString(message, kp.pk);
      final decrypted = await decryptString(encrypted, kp.sk);

      expect(decrypted, equals(message));
    });

    test('Encrypt and decrypt long message', () async {
      final kp = keyGen();
      final message = List.generate(10000, (i) => 'A').join();

      final encrypted = await encryptString(message, kp.pk);
      final decrypted = await decryptString(encrypted, kp.sk);

      expect(decrypted, equals(message));
    });

    test('Encrypt and decrypt special characters', () async {
      final kp = keyGen();
      final message = "!@#\$%^&*()_+{}:|<>?~`-=[]\\;',./";

      final encrypted = await encryptString(message, kp.pk);
      final decrypted = await decryptString(encrypted, kp.sk);

      expect(decrypted, equals(message));
    });

    test('Encrypt and decrypt non-ASCII characters', () async {
      final kp = keyGen();
      final message = "こんにちは世界! ¡Hola! Привет! 你好!";

      final encrypted = await encryptString(message, kp.pk);
      final decrypted = await decryptString(encrypted, kp.sk);

      expect(decrypted, equals(message));
    });
  });
}
