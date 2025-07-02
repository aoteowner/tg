import 'dart:async';
import 'dart:typed_data';

import 'package:nop/nop.dart';

import 'frame.dart';
import 'obfuscation.dart';

class BaseTransformer {
  BaseTransformer(
    this._receiver,
    // this._msgsToAck,
    this._obfuscation,
    this.key,
  ) {
    _subscription = _receiver.listen(_readFrame);
  }

  BaseTransformer.unEncrypted(
    this._receiver,
    this._obfuscation,
  ) : key = const [] {
    _subscription = _receiver.listen(_readFrame);
  }

  StreamSubscription<Uint8List>? _subscription;

  Future<void> dispose() async {
    await _subscription?.cancel();
    _streamController.close();
  }

  final _streamController = StreamController<Frame>.broadcast();
  Stream<Frame> get stream => _streamController.stream;

  final Stream<Uint8List> _receiver;
  final Obfuscation? _obfuscation;
  Uint8List _read = Uint8List(0);
  final List<int> key;

  void _readFrame(Uint8List l) {
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
