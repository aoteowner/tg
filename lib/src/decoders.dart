import 'dart:async';
import 'dart:typed_data';

import 'package:nop/nop.dart';

import 'frame.dart';
import 'obfuscation.dart';

class BaseTransformer {
  BaseTransformer(this._obfuscation, this.key);

  BaseTransformer.unEncrypted(this._obfuscation) : key = const [];

  Future<void> dispose() async {
    _streamController.close();
  }

  final _streamController = StreamController<Frame>.broadcast();
  Stream<Frame> get stream => _streamController.stream;

  final Obfuscation? _obfuscation;
  Uint8List _read = Uint8List(0);
  final List<int> key;

  void readFrame(Uint8List l) {
    final length = l.length + _read.length;
    final buf = Uint8List(length);
    buf.setRange(0, _read.length, _read);
    buf.setRange(_read.length, length, l);
    _read = buf;

    for (;;) {
      if (_read.length < 4) break;

      final temp = _read.sublist(0, 4);
      _obfuscation?.recv.encryptDecrypt(temp, 4);
      final length = temp.buffer.asByteData().getInt32(0, Endian.little);

      if (_read.length < length) break;
      _read = _read.sublist(4);

      try {
        final buffer = _read.sublist(0, length);
        final frame = Frame.parse(buffer, _obfuscation, key);
        _streamController.add(frame);
      } catch (e, s) {
        Log.e('parse error: $e\n$s');
      }

      _read = _read.sublist(length);
    }
  }
}
