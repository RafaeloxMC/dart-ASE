import 'dart:math';

bool hasEnoughEntropy(List<int> data, double minEntropy) {
  final counts = <int, int>{};
  for (var v in data) {
    counts[v] = (counts[v] ?? 0) + 1;
  }
  double entropy = 0;
  for (var count in counts.values) {
    final p = count / data.length;
    entropy -= p * (log(p) / log(2));
  }
  return entropy >= minEntropy;
}
