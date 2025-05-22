import 'dart:math';

/// Polynomial degree (security level)
const int n = 256;

/// Modulus (prime)
const int q = 3329;

/// Lattice dimension
const int k = 3;

/// Noise parameter
const int eta = 1;

/// Secure RNG
final rnd = Random.secure();
