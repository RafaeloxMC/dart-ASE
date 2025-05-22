import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:dart_ase/src/constants.dart';

final aesGcm = AesGcm.with256bits();
final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

Future<Uint8List> deriveAesKey(Uint8List r) async {
  final salt = Uint8List(32);
  for (var i = 0; i < salt.length; i++) {
    salt[i] = rnd.nextInt(256);
  }
  final info = utf8.encode('AES-GCM key');

  final secretKey = await hkdf.deriveKey(
    secretKey: SecretKey(r),
    nonce: salt,
    info: info,
  );

  return Uint8List.fromList(await secretKey.extractBytes());
}

Future<Uint8List> deriveAesKeyWithSalt(Uint8List r, Uint8List salt) async {
  final info = utf8.encode('AES-GCM key');

  final secretKey = await hkdf.deriveKey(
    secretKey: SecretKey(r),
    nonce: salt,
    info: info,
  );

  return Uint8List.fromList(await secretKey.extractBytes());
}
