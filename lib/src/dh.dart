import 'dart:math';
import 'dart:typed_data';

/// ported from https://github.com/tdlib/td/blob/master/tdutils/td/utils/crypto.cpp#L103
///
/// Returns ulong.
int pqFactorize(int pq) {
  if (pq < 2) return 1;
  final random = Random();
  int g = 0;

  for (int i = 0, iter = 0; i < 3 || iter < 1000; i++) {
    final q = (17 + random.nextInt(15)) % (pq - 1);
    var x =
        (random.nextInt(1 << 32) + random.nextInt(1 << 32) << 31) % (pq - 1) +
            1;
    var y = x;
    int lim = 1 << (min(5, i) + 18);
    for (int j = 1; j < lim; j++) {
      iter++;
      // x = (q + x * x) % pq
      var res = q;
      var a = x;

      while (x != 0) {
        if ((x & 1) != 0) {
          res = (res + a) % pq;
        }
        a = (a + a) % pq;
        x >>= 1;
      }
      x = res;
      final z = x < y ? pq + x - y : x - y;
      g = _gcd(z, pq);
      if (g != 1) {
        break;
      }

      if ((j & (j - 1)) == 0) {
        y = x;
      }
    }
    if (g > 1 && g < pq) {
      break;
    }
  }
  if (g != 0) {
    final other = pq ~/ g;
    if (other < g) {
      g = other;
    }
  }
  return g;
}

int _gcd(int left, int right) {
  while (right != 0) {
    final num = left % right;
    left = right;
    right = num;
  }
  return left;
}

class AesKeyIV {
  const AesKeyIV(this.key, this.iv);

  final Uint8List key;
  final Uint8List iv;
}
