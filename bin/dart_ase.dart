import 'dart:convert';
import 'dart:io';
import 'package:dart_ase/src/hybrid/hybrid_pke.dart';
import 'package:dart_ase/src/io/deserialize.dart';
import 'package:dart_ase/src/io/serialize.dart';
import 'package:dart_ase/src/kem/kem.dart';
import 'package:dart_ase/src/kem/keypair.dart';
import 'package:dart_ase/src/poly/polynominal.dart';
import 'package:dart_ase/src/poly/polyvec.dart';

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
      var sk = ASEPrivateKey(PolyVec(
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
