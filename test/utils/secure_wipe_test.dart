import 'dart:typed_data';
import 'package:dart_ase/utils/secure_wipe.dart';
import 'package:test/test.dart';

void main() {
  group('Secure wiping', () {
    test('secureWipe zeros out all bytes', () {
      final data = Uint8List.fromList(List.generate(100, (i) => i));

      secureWipe(data);

      for (int i = 0; i < data.length; i++) {
        expect(data[i], equals(0));
      }
    });

    test('secureWipe with empty data', () {
      final data = Uint8List(0);

      // Should not throw an exception
      expect(() => secureWipe(data), returnsNormally);
    });
  });

  group('Constant time comparison', () {
    test('Equal arrays return 0', () {
      final a = [1, 2, 3, 4, 5];
      final b = [1, 2, 3, 4, 5];

      expect(constantTimeCompare(a, b), equals(0));
    });

    test('Different arrays return non-zero', () {
      final a = [1, 2, 3, 4, 5];
      final b = [1, 2, 3, 4, 6];

      expect(constantTimeCompare(a, b), isNot(equals(0)));
    });

    test('Arrays of different lengths return non-zero', () {
      final a = [1, 2, 3, 4, 5];
      final b = [1, 2, 3, 4];

      expect(constantTimeCompare(a, b), equals(1));
    });

    test('Empty arrays are equal', () {
      final a = <int>[];
      final b = <int>[];

      expect(constantTimeCompare(a, b), equals(0));
    });
  });
}
