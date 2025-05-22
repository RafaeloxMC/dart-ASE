import 'package:dart_ase/utils/entropy.dart';
import 'package:test/test.dart';

void main() {
  group('Entropy calculation', () {
    test('Uniform distribution has high entropy', () {
      final uniformData = List<int>.generate(256, (i) => i);

      expect(hasEnoughEntropy(uniformData, 7.5), isTrue);
    });

    test('Repeated values have low entropy', () {
      final repeatedData = List<int>.filled(256, 42);

      expect(hasEnoughEntropy(repeatedData, 0.5), isFalse);
    });

    test('Binary data has limited entropy', () {
      final binaryData = List<int>.generate(256, (i) => i % 2);

      expect(hasEnoughEntropy(binaryData, 0.9), isTrue);
      expect(hasEnoughEntropy(binaryData, 1.5), isFalse);
    });

    test('Empty list edge case', () {
      final emptyList = <int>[];

      expect(() => hasEnoughEntropy(emptyList, 1.0), returnsNormally);
      expect(hasEnoughEntropy(emptyList, 0.1), isFalse);
    });

    test('Single value edge case', () {
      final singleValue = [42];

      expect(hasEnoughEntropy(singleValue, 0.1), isFalse);
    });
  });
}
