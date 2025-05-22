import 'dart:typed_data';

void secureWipe(Uint8List data) {
  for (var i = 0; i < data.length; i++) {
    data[i] = 0;
  }
}

int constantTimeCompare(List<int> a, List<int> b) {
  if (a.length != b.length) return 1;
  int result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result;
}
