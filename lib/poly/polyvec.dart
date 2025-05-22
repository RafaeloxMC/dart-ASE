import 'package:dart_ase/constants.dart';
import 'package:dart_ase/poly/polynominal.dart';

class PolyVec {
  final List<Poly> vec;
  PolyVec([List<Poly>? v]) : vec = List.generate(k, (_) => Poly()) {
    if (v != null) {
      if (v.length != k) throw ArgumentError('PolyVec needs $k polys');
      for (var i = 0; i < k; i++) vec[i] = v[i];
    }
  }
  PolyVec operator +(PolyVec o) =>
      PolyVec(List.generate(k, (i) => vec[i] + o.vec[i]));

  static PolyVec mulMatrix(List<PolyVec> A, PolyVec s) {
    var r = PolyVec();
    for (var i = 0; i < k; i++) {
      var acc = Poly();
      for (var j = 0; j < k; j++) {
        acc = acc + Poly.polymul(A[i].vec[j], s.vec[j]);
      }
      r.vec[i] = acc;
    }
    return r;
  }
}
