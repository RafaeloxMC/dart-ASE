import 'package:dart_ase/constants.dart';

class Poly {
  final List<int> coeffs;
  Poly([List<int>? c]) : coeffs = List.filled(n, 0) {
    if (c != null) {
      if (c.length != n) throw ArgumentError('Poly needs $n coeffs');
      for (var i = 0; i < n; i++) coeffs[i] = c[i] % q;
    }
  }
  Poly operator +(Poly o) =>
      Poly(List.generate(n, (i) => (coeffs[i] + o.coeffs[i]) % q));
  Poly operator -(Poly o) =>
      Poly(List.generate(n, (i) => (coeffs[i] - o.coeffs[i] + q) % q));

  static Poly polymul(Poly a, Poly b) {
    var c = List<int>.filled(n, 0);
    for (var i = 0; i < n; i++) {
      for (var j = 0; j < n; j++) {
        var kidx = (i + j) % n;
        var prod = a.coeffs[i] * b.coeffs[j];
        var sign = (i + j < n) ? 1 : -1;
        c[kidx] = (c[kidx] + sign * prod) % q;
        if (c[kidx] < 0) c[kidx] += q;
      }
    }
    return Poly(c);
  }

  static Poly randomUniform() {
    return Poly(List<int>.generate(n, (_) => rnd.nextInt(q)));
  }

  static Poly sampleNoise() {
    var p = Poly();
    for (var i = 0; i < n; i++) {
      p.coeffs[i] = rnd.nextInt(2 * eta + 1) - eta;
    }
    return p;
  }
}
