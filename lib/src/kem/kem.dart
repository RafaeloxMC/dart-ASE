import 'package:dart_ase/src/constants.dart';
import 'package:dart_ase/src/kem/keypair.dart';
import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';
import 'package:dart_ase/src/utils/entropy.dart';

ASEKeyPair keyGen() {
  var A = List<PolyVec>.generate(
      k, (_) => PolyVec(List.generate(k, (_) => Poly.randomUniform())));
  var s = PolyVec(List.generate(k, (_) => Poly.sampleNoise()));
  var e = PolyVec(List.generate(k, (_) => Poly.sampleNoise()));
  var b = PolyVec.mulMatrix(A, s) + e;

  List<int> allCoeffs = [];
  for (var i = 0; i < k; i++) {
    allCoeffs.addAll(s.vec[i].coeffs);
  }

  if (!hasEnoughEntropy(allCoeffs, 0.7)) {
    throw StateError("Generated key doesn't have enough entropy");
  }

  return ASEKeyPair(ASEPublicKey(A, b), ASEPrivateKey(s));
}

ASECiphertextKEM kemEncap(ASEPublicKey pk, PolyVec r) {
  var e1 = PolyVec(List.generate(k, (_) => Poly.sampleNoise()));
  var e2 = Poly.sampleNoise();
  var AT = List<PolyVec>.generate(
    k,
    (i) => PolyVec(List.generate(k, (j) => pk.A[j].vec[i])),
  );
  var u = PolyVec.mulMatrix(AT, r) + e1;

  var br = Poly();
  for (var i = 0; i < k; i++) {
    br = br + Poly.polymul(pk.b.vec[i], r.vec[i]);
  }

  var halfQ = q ~/ 2;
  var emb = List<int>.generate(n, (i) => (r.vec[0].coeffs[i] * halfQ) % q);
  var v = (br + e2) + Poly(emb);
  return ASECiphertextKEM(u, v);
}

PolyVec kemDecap(ASECiphertextKEM ct, ASEPrivateKey sk) {
  try {
    var us = Poly();
    for (var i = 0; i < k; i++) {
      us = us + Poly.polymul(ct.u.vec[i], sk.s.vec[i]);
    }
    var diff = ct.v - us;
    var centered = diff.coeffs.map((x) {
      var y = x;
      if (y > q ~/ 2) y -= q;
      return y;
    }).toList();
    var thr = q ~/ 4;
    var bits = centered.map((y) => y.abs() > thr ? 1 : 0).toList();
    return PolyVec([Poly(bits), Poly(), Poly()]);
  } catch (e) {
    throw StateError('KEM decapsulation failed: ${e.toString()}');
  }
}
