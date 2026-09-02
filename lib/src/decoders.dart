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

      final temp = Uint8List.sublistView(_read, 0, 4);
      _obfuscation?.recv.encryptDecrypt(temp, 4);
      final length = temp.buffer.asByteData(0, 4).getInt32(0, Endian.little);
      if (length < 0) {
        Log.e("error: length $length.");
        _streamController.addError("error: length $length.");
        dispose();
        _read = Uint8List(0);
        return;
      }

      if (_read.length < length + 4) break;
      _read = _read.sublist(4);

      try {
        final buffer = Uint8List.sublistView(_read, 0, length);
        final frame = Frame.parse(buffer, _obfuscation, key);
        _streamController.add(frame);
      } catch (e, s) {
        _streamController.addError(e, s);
        dispose();
        Log.e('parse error: $e\n$s');
      }

      _read = _read.sublist(length);
    }
  }
}
