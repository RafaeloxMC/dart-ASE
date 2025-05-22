import 'package:dart_ase/constants.dart';
import 'package:dart_ase/poly/polynominal.dart';
import 'package:dart_ase/poly/polyvec.dart';
import 'package:test/test.dart';

void main() {
  group('PolyVec operations', () {
    test('PolyVec initialization', () {
      final pv = PolyVec();

      expect(pv.vec.length, equals(k));
      for (final poly in pv.vec) {
        expect(poly.coeffs.length, equals(n));
      }
    });

    test('PolyVec addition', () {
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

      final sum = pv1 + pv2;

      expect(sum.vec[0].coeffs[0], equals(11));
      expect(sum.vec[1].coeffs[0], equals(33));
      expect(sum.vec[2].coeffs[0], equals(55));
    });

    test('Matrix multiplication', () {
      final A = List<PolyVec>.generate(
          k,
          (i) => PolyVec(List.generate(
              k, (j) => Poly([i + j + 1, ...List.filled(n - 1, 0)]))));

      final s =
          PolyVec(List.generate(k, (i) => Poly([1, ...List.filled(n - 1, 0)])));

      final result = PolyVec.mulMatrix(A, s);

      expect(result.vec.length, equals(k));

      int expectedSum = 0;
      for (int j = 0; j < k; j++) {
        expectedSum += (0 + j + 1); // A[0][j] * s[j][0]
      }
      expect(result.vec[0].coeffs[0], equals(expectedSum));
    });

    test('PolyVec constructor with invalid vector length', () {
      expect(() => PolyVec([Poly()]), throwsA(isA<ArgumentError>()));
    });

    test('PolyVec initialization with given vector', () {
      final polys =
          List.generate(k, (i) => Poly([i, ...List.filled(n - 1, 0)]));
      final pv = PolyVec(polys);

      for (int i = 0; i < k; i++) {
        expect(pv.vec[i].coeffs[0], equals(i));
      }
    });
  });
}
