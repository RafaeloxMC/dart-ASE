import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

// === Parameters ===
const int n = 256, q = 3329, k = 3, eta = 1;
final _rnd = Random.secure();

// AES‑GCM algorithm and HKDF
final _aesGcm = AesGcm.with256bits();
final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

Future<Uint8List> deriveAesKey(Uint8List r) async {
  final salt = Uint8List(32);
  final info = utf8.encode('AES-GCM key');

  final secretKey = await _hkdf.deriveKey(
    secretKey: SecretKey(r),
    nonce: salt,
    info: info,
  );

  return Uint8List.fromList(await secretKey.extractBytes());
}

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
        c[kidx] = (c[kidx] + (i + j < n ? prod : -prod)) % q;
      }
    }
    return Poly(c);
  }

  static Poly randomUniform() {
    return Poly(List<int>.generate(n, (_) => _rnd.nextInt(q)));
  }

  static Poly sampleNoise() =>
      Poly(List.generate(n, (_) => _rnd.nextInt(2 * eta + 1) - eta));
}

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

// === KEM classes ===
class PublicKey {
  final List<PolyVec> A;
  final PolyVec b;
  PublicKey(this.A, this.b);
}

class PrivateKey {
  final PolyVec s;
  PrivateKey(this.s);
}

class KeyPair {
  final PublicKey pk;
  final PrivateKey sk;
  KeyPair(this.pk, this.sk);
}

class CiphertextKEM {
  final PolyVec u;
  final Poly v;
  CiphertextKEM(this.u, this.v);
}

// === CPA KEM implementation (using polymul) ===
KeyPair keyGen() {
  var A = List<PolyVec>.generate(
      k, (_) => PolyVec(List.generate(k, (_) => Poly.randomUniform())));
  var s = PolyVec(List.generate(k, (_) => Poly.sampleNoise()));
  var e = PolyVec(List.generate(k, (_) => Poly.sampleNoise()));
  var b = PolyVec.mulMatrix(A, s) + e;
  return KeyPair(PublicKey(A, b), PrivateKey(s));
}

CiphertextKEM kemEncap(PublicKey pk, PolyVec r) {
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
  return CiphertextKEM(u, v);
}

PolyVec kemDecap(CiphertextKEM ct, PrivateKey sk) {
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
}

// === Hybrid PKE: KEM + AES‑GCM AEAD ===
class CombinedCipher {
  final CiphertextKEM kemCt;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final Uint8List aad; // optional
  CombinedCipher(this.kemCt, this.nonce, this.ciphertext, this.aad);
}

Future<CombinedCipher> encryptString(String pt, PublicKey pk) async {
  var r = PolyVec(
      List.generate(k, (_) => Poly(List.generate(n, (_) => _rnd.nextInt(2)))));
  var kemCt = kemEncap(pk, r);
  var flatR = Uint8List.fromList(r.vec[0].coeffs);
  var aesKey = await deriveAesKey(flatR);

  final nonce = _aesGcm.newNonce();
  final secretBox = await _aesGcm.encrypt(
    utf8.encode(pt),
    secretKey: SecretKey(aesKey),
    nonce: nonce,
    aad: <int>[],
  );
  return CombinedCipher(
    kemCt,
    Uint8List.fromList(secretBox.nonce),
    Uint8List.fromList(secretBox.cipherText + secretBox.mac.bytes),
    Uint8List(0),
  );
}

Future<String> decryptString(CombinedCipher cc, PrivateKey sk) async {
  var rRec = kemDecap(cc.kemCt, sk);
  var flatR = Uint8List.fromList(rRec.vec[0].coeffs);
  var aesKey = await deriveAesKey(flatR);

  final nonce = cc.nonce;
  final tagLen = 16;
  final ctLen = cc.ciphertext.length - tagLen;
  final cipherText = cc.ciphertext.sublist(0, ctLen);
  final mac = cc.ciphertext.sublist(ctLen);
  final secretBox = SecretBox(
    cipherText,
    nonce: nonce,
    mac: Mac(mac),
  );
  try {
    final clear = await _aesGcm.decrypt(
      secretBox,
      secretKey: SecretKey(aesKey),
    );
    return utf8.decode(clear);
  } catch (e) {
    throw StateError('Decryption failed: authentication error');
  }
}

// === Serialization ===
String serializePublicKey(PublicKey pk) => jsonEncode({
      'A': pk.A.map((pv) => pv.vec.map((p) => p.coeffs).toList()).toList(),
      'b': pk.b.vec.map((p) => p.coeffs).toList(),
    });

PublicKey deserializePublicKey(String path) {
  var m = jsonDecode(File(path).readAsStringSync());
  var A = (m['A'] as List)
      .map((pv) => PolyVec(
          (pv as List).map((c) => Poly(List<int>.from(c as List))).toList()))
      .toList();
  var bVec =
      (m['b'] as List).map((c) => Poly(List<int>.from(c as List))).toList();
  return PublicKey(A, PolyVec(bVec));
}

String serializeCombinedCipher(CombinedCipher cc) => jsonEncode({
      'kemCt': {
        'u': cc.kemCt.u.vec.map((p) => p.coeffs).toList(),
        'v': cc.kemCt.v.coeffs,
      },
      'nonce': cc.nonce.toList(),
      'ciphertext': cc.ciphertext.toList(),
    });

CombinedCipher deserializeCombinedCipher(String path) {
  var m = jsonDecode(File(path).readAsStringSync()) as Map;
  var kem = m['kemCt'] as Map;
  var uList = kem['u'] as List;
  var polys = uList.map((elem) => Poly(List<int>.from(elem as List))).toList();
  var uVec = PolyVec(polys);
  var v = Poly(List<int>.from(kem['v'] as List));
  var nonce = Uint8List.fromList(List<int>.from(m['nonce'] as List));
  var sym = Uint8List.fromList(List<int>.from(m['ciphertext'] as List));
  return CombinedCipher(CiphertextKEM(uVec, v), nonce, sym, Uint8List(0));
}

// === CLI ===
Future<void> main(List<String> args) async {
  if (args.isEmpty) return _usage();
  switch (args[0]) {
    case 'gen':
      var kp = keyGen();
      File('pubkey.json').writeAsStringSync(serializePublicKey(kp.pk));
      File('privkey.json').writeAsStringSync(
          jsonEncode({'s': kp.sk.s.vec.map((p) => p.coeffs).toList()}));
      print('Generated pubkey.json and privkey.json');
      break;
    case 'enc':
      if (args.length != 3)
        return stderr.writeln('Usage: enc <pubkey.json> <"plaintext"');
      var pk = deserializePublicKey(args[1]);
      var cc = await encryptString(args[2], pk);
      File('ciphertext.json').writeAsStringSync(serializeCombinedCipher(cc));
      print('Encrypted to ciphertext.json');
      break;
    case 'dec':
      if (args.length != 3)
        return stderr.writeln('Usage: dec <privkey.json> <ciphertext.json>');
      var priv = jsonDecode(File(args[1]).readAsStringSync());
      var sk = PrivateKey(PolyVec(
          (priv['s'] as List).map((c) => Poly(List<int>.from(c))).toList()));
      var cc = deserializeCombinedCipher(args[2]);
      var pt = await decryptString(cc, sk);
      print('Decrypted plaintext:');
      print(pt);
      break;
    default:
      _usage();
  }
}

void _usage() {
  final scriptName = Platform.script.pathSegments.last;
  final dartPrefix = scriptName.endsWith('.dart') ? "dart run " : "";
  print('''
Usage:
  $dartPrefix$scriptName gen
    → writes pubkey.json & privkey.json

  $dartPrefix$scriptName enc pubkey.json "Your message"
    → writes ciphertext.json

  $dartPrefix$scriptName dec privkey.json ciphertext.json
    → prints decrypted message''');
}
