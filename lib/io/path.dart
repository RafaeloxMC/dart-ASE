bool isPathSafe(String path) {
  if (path.contains('..') || path.contains('/') || path.contains('\\')) {
    return false;
  }
  if (!path.endsWith('.json')) {
    return false;
  }
  return true;
}
