import 'package:dart_ase/constants.dart';
import 'package:dart_ase/poly/polynominal.dart';
import 'package:test/test.dart';

void main() {
  group('Polynomial operations', () {
    test('Polynomial addition', () {
      final p1 = Poly([1, 2, 3, 4, ...List.filled(n - 4, 0)]);
      final p2 = Poly([5, 6, 7, 8, ...List.filled(n - 4, 0)]);

      final sum = p1 + p2;

      expect(sum.coeffs.sublist(0, 4), equals([6, 8, 10, 12]));
      expect(sum.coeffs.length, equals(n));
    });

    test('Polynomial subtraction', () {
      final p1 = Poly([10, 20, 30, 40, ...List.filled(n - 4, 0)]);
      final p2 = Poly([5, 5, 10, 20, ...List.filled(n - 4, 0)]);

      final diff = p1 - p2;

      expect(diff.coeffs.sublist(0, 4), equals([5, 15, 20, 20]));
      expect(diff.coeffs.length, equals(n));
    });

    test('Polynomial multiplication', () {
      final p1 = Poly([1, 1, 0, 0, ...List.filled(n - 4, 0)]);
      final p2 = Poly([1, 1, 0, 0, ...List.filled(n - 4, 0)]);

      final product = Poly.polymul(p1, p2);

      expect(product.coeffs[0], equals(1));
      expect(product.coeffs[1], equals(2));
      expect(product.coeffs[2], equals(1));
    });

    test('Random polynomial generation', () {
      final p = Poly.randomUniform();

      expect(p.coeffs.length, equals(n));
      for (final coeff in p.coeffs) {
        expect(coeff >= 0 && coeff < q, isTrue);
      }
    });

    test('Noise sampling', () {
      final p = Poly.sampleNoise();

      expect(p.coeffs.length, equals(n));
      for (final coeff in p.coeffs) {
        expect(coeff >= -eta && coeff <= eta, isTrue);
      }
    });

    test('Polynomial constructor with invalid coefficients length', () {
      expect(() => Poly([1, 2, 3]), throwsA(isA<ArgumentError>()));
    });

    test('Polynomial modular reduction', () {
      final p = Poly([q + 1, 2 * q + 2, 3 * q + 3, ...List.filled(n - 3, 0)]);

      expect(p.coeffs[0], equals(1));
      expect(p.coeffs[1], equals(2));
      expect(p.coeffs[2], equals(3));
    });
  });
}
