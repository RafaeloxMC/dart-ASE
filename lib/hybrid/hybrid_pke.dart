import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dart_ase/constants.dart';
import 'package:dart_ase/kem/kem.dart';
import 'package:dart_ase/kem/keypair.dart';
import 'package:dart_ase/poly/polynominal.dart';
import 'package:dart_ase/poly/polyvec.dart';
import 'package:dart_ase/utils/hkdf_aes.dart';
import 'package:dart_ase/utils/secure_wipe.dart';

/// Final class for the combined ciphertext
/// It contains the KEM ciphertext, nonce, ciphertext, AAD, and salt
class ASECombinedCipher {
  final ASECiphertextKEM kemCt;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final Uint8List aad;
  final Uint8List salt;
  ASECombinedCipher(
      this.kemCt, this.nonce, this.ciphertext, this.aad, this.salt);
}

/// Encrypts a string using the hybrid PKE scheme
/// It uses the public key (pk) to generate a shared secret and then uses AES-GCM to encrypt the plaintext (pt)
Future<ASECombinedCipher> encryptString(String pt, ASEPublicKey pk) async {
  var r = PolyVec(
      List.generate(k, (_) => Poly(List.generate(n, (_) => rnd.nextInt(2)))));
  var kemCt = kemEncap(pk, r);
  var flatR = Uint8List.fromList(r.vec[0].coeffs);

  final salt = Uint8List(32);
  for (var i = 0; i < salt.length; i++) {
    salt[i] = rnd.nextInt(256);
  }

  var aesKey = await deriveAesKeyWithSalt(flatR, salt);

  final nonce = aesGcm.newNonce();
  final secretBox = await aesGcm.encrypt(
    utf8.encode(pt),
    secretKey: SecretKey(aesKey),
    nonce: nonce,
    aad: <int>[],
  );

  return ASECombinedCipher(
    kemCt,
    Uint8List.fromList(secretBox.nonce),
    Uint8List.fromList(secretBox.cipherText + secretBox.mac.bytes),
    Uint8List(0),
    salt,
  );
}

/// Decrypts a string using the hybrid PKE scheme
/// It uses the private key (sk) to generate a shared secret and then uses AES-GCM to decrypt the ciphertext (ct)
Future<String> decryptString(ASECombinedCipher cc, ASEPrivateKey sk) async {
  var rRec = kemDecap(cc.kemCt, sk);
  var flatR = Uint8List.fromList(rRec.vec[0].coeffs);
  var aesKey = await deriveAesKeyWithSalt(flatR, cc.salt);

  try {
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

    final clear = await aesGcm.decrypt(
      secretBox,
      secretKey: SecretKey(aesKey),
    );

    String result = utf8.decode(clear);
    secureWipe(flatR);
    secureWipe(aesKey);
    return result;
  } catch (e) {
    secureWipe(flatR);
    secureWipe(aesKey);
    throw StateError('Decryption failed: authentication error');
  }
}
