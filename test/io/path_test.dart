import 'package:dart_ase/io/path.dart';
import 'package:test/test.dart';

void main() {
  group('Path safety', () {
    test('Valid path is safe', () {
      expect(isPathSafe('validfile.json'), isTrue);
    });

    test('Path with directory traversal is unsafe', () {
      expect(isPathSafe('../somefile.json'), isFalse);
      expect(isPathSafe('../../somefile.json'), isFalse);
      expect(isPathSafe('dir/../file.json'), isFalse);
    });

    test('Path with directory separator is unsafe', () {
      expect(isPathSafe('dir/file.json'), isFalse);
      expect(isPathSafe('dir\\file.json'), isFalse);
    });

    test('Non-json file is unsafe', () {
      expect(isPathSafe('file.txt'), isFalse);
      expect(isPathSafe('file.js'), isFalse);
      expect(isPathSafe('file'), isFalse);
      expect(isPathSafe('file.json.exe'), isFalse);
    });

    test('File with invalid characters', () {
      expect(isPathSafe('file name.json'), isTrue); // spaces are allowed
      expect(isPathSafe('file_name.json'), isTrue); // underscores are allowed
      expect(isPathSafe('file-name.json'), isTrue); // hyphens are allowed
    });
  });
}
