import 'dart:math' as math;
import 'package:dart_ase/constants.dart';
import 'package:dart_ase/kem/kem.dart';
import 'package:dart_ase/kem/keypair.dart';
import 'package:dart_ase/poly/polynominal.dart';
import 'package:dart_ase/poly/polyvec.dart';
import 'package:test/test.dart';

void main() {
  final rnd = math.Random.secure();

  group('Key generation and KEM', () {
    test('keyGen produces valid keypair', () {
      final kp = keyGen();

      expect(kp.pk.A.length, equals(k));
      expect(kp.pk.b.vec.length, equals(k));
      expect(kp.sk.s.vec.length, equals(k));
    });

    test('KEM encapsulation and decapsulation', () {
      final kp = keyGen();
      final r = PolyVec(List.generate(
          k, (_) => Poly(List.generate(n, (_) => rnd.nextInt(2)))));

      final ct = kemEncap(kp.pk, r);

      expect(ct.u.vec.length, equals(k));

      final recovered = kemDecap(ct, kp.sk);

      int matchingBits = 0;
      for (int i = 0; i < n; i++) {
        if (recovered.vec[0].coeffs[i] == r.vec[0].coeffs[i]) {
          matchingBits++;
        }
      }

      final recoveryRate = matchingBits / n;
      expect(recoveryRate > 0.9, isTrue);
    });

    test('KEM encapsulation with zero vector', () {
      final kp = keyGen();
      final r = PolyVec(List.generate(k, (_) => Poly()));

      final ct = kemEncap(kp.pk, r);
      final recovered = kemDecap(ct, kp.sk);

      int nonZeroCount = 0;
      for (int i = 0; i < n; i++) {
        if (recovered.vec[0].coeffs[i] != 0) {
          nonZeroCount++;
        }
      }

      expect(nonZeroCount < n / 10, isTrue,
          reason: 'Most coefficients should be recovered as zero');
    });

    test('KeyPair structure', () {
      final A = List<PolyVec>.generate(
          k, (_) => PolyVec(List.generate(k, (_) => Poly.randomUniform())));
      final b = PolyVec();
      final s = PolyVec();

      final pk = ASEPublicKey(A, b);
      final sk = ASEPrivateKey(s);
      final kp = ASEKeyPair(pk, sk);

      expect(kp.pk, same(pk));
      expect(kp.sk, same(sk));
    });

    test('ASECiphertextKEM structure', () {
      final u = PolyVec();
      final v = Poly();

      final ct = ASECiphertextKEM(u, v);

      expect(ct.u, same(u));
      expect(ct.v, same(v));
    });
  });
}
