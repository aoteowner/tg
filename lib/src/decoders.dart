part of '../tg.dart';

class _BaseTransformer {
  _BaseTransformer(
    this._receiver,
    // this._msgsToAck,
    this._obfuscation,
    this.key,
  ) {
    _subscription = _receiver.listen(_readFrame);
  }

  _BaseTransformer.unEncrypted(
    this._receiver,
    // this._msgsToAck,
    this._obfuscation,
  ) : key = const [] {
    _subscription = _receiver.listen(_readFrame);
  }

  StreamSubscription<List<int>>? _subscription;

  Future<void> dispose() async {
    await _subscription?.cancel();
  }

  final _streamController = StreamController<Frame>.broadcast();
  Stream<Frame> get stream => _streamController.stream;

  final Stream<List<int>> _receiver;
  final Obfuscation? _obfuscation;
  // final Set<int> _msgsToAck;
  final List<int> _read = [];
  int? _length;
  final List<int> key;

  void _readFrame(List<int> l) {
    _read.addAll(l);
    while (true) {
      if (_length == null && _read.length >= 4) {
        final temp = _read.take(4).toList();
        _obfuscation?.recv.encryptDecrypt(temp, 4);

        _length = ByteData.sublistView(Uint8List.fromList(temp))
            .getInt32(0, Endian.little);
      }

      final length = _length;
      if (length == null || _read.length < length + 4) break;

      final buffer = Uint8List.fromList(_read.skip(4).take(length).toList());
      _read.removeRange(0, length + 4);
      _length = null;

      final frame = Frame.parse(buffer, _obfuscation, key);
      // final seqno = frame.seqno;

      // if (seqno != null && (seqno & 1) != 0) {
      //   _msgsToAck.add(frame.messageId);
      // }

      _streamController.add(frame);
    }
  }
}
