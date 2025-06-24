part of '../tg.dart';

class Client extends t.Client {
  Client({
    required this.receiver,
    required this.sender,
    required this.obfuscation,
    required this.authorizationKey,
  }) {
    _transformer = _BaseTransformer(
      receiver,
      _msgsToAck,
      obfuscation,
      authorizationKey.key,
    );

    _transformer.stream.listen(_listener);
  }

  int? _seqno;
  void _listener(_Frame frame) {
    _seqno = frame.seqno;
    _handleIncomingMessage(frame.message);
  }

  static Future<AuthorizationKey> authorize(
    Stream<Uint8List> receiver,
    Sink<List<int>> sender,
    Obfuscation obfuscation,
  ) async {
    final Set<int> msgsToAck = {};

    final uot = _BaseTransformer.unEncrypted(
      receiver,
      msgsToAck,
      obfuscation,
    );

    final idSeq = _MessageIdSequenceGenerator();
    final dh = _DiffieHellman(
      sender,
      uot.stream,
      obfuscation,
      idSeq,
    );
    final ak = await dh.exchange();

    await uot.dispose();
    return ak;
  }

  void start() {
    sender.add(obfuscation.preamble);
  }

  final AuthorizationKey authorizationKey;
  final Obfuscation obfuscation;
  final Stream<Uint8List> receiver;
  final Sink<List<int>> sender;

  late final _BaseTransformer _transformer;

  final Map<int, Completer<t.Result>> _pending = {};

  final _streamController = StreamController<UpdatesBase>.broadcast();

  Stream<UpdatesBase> get stream => _streamController.stream;

  void _handleIncomingMessage(TlObject msg) {
    switch (msg) {
      case UpdatesBase():
        _streamController.add(msg);
      case MsgContainer():
        for (final message in msg.messages) {
          _handleIncomingMessage(message);
        }

      case Msg():
        _handleIncomingMessage(msg.body);
      case BadMsgNotification():
        if (_seqno != null) {
          _idSeq._seqno = _seqno!;
        }
        final badMsgId = msg.badMsgId;
        final task = _pending[badMsgId];
        task?.completeError(TryAgainException(msg));
        _pending.remove(badMsgId);
      case BadServerSalt salt:
        authorizationKey.salt = salt.newServerSalt;
        final badMsgId = msg.badMsgId;
        final task = _pending[badMsgId];
        task?.completeError(TryAgainException(salt));
        _pending.remove(badMsgId);
      case RpcResult():
        final reqMsgId = msg.reqMsgId;
        final task = _pending[reqMsgId];

        final result = msg.result;

        if (result is RpcError) {
          task?.complete(t.Result.error(result));
          _pending.remove(reqMsgId);
          return;
        } else if (result is GzipPacked) {
          final gZippedData =
              const GZipDecoder().decodeBytes(result.packedData);

          final newObj =
              BinaryReader(Uint8List.fromList(gZippedData)).readObject();

          final newRpcResult = RpcResult(reqMsgId: reqMsgId, result: newObj);
          _handleIncomingMessage(newRpcResult);
          return;
        }

        task?.complete(t.Result.ok(msg.result));
        _pending.remove(reqMsgId);
      case GzipPacked():
        final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
        final newObj =
            BinaryReader(Uint8List.fromList(gZippedData)).readObject();
        _handleIncomingMessage(newObj);
    }
  }

  final _idSeq = _MessageIdSequenceGenerator();
  final Set<int> _msgsToAck = {};

  @override
  Future<t.Result<t.TlObject>> invoke(t.TlMethod method) {
    final preferEncryption = authorizationKey.id != 0;
    final msgsToAck = _msgsToAck;

    final completer = Completer<t.Result>();
    final m = _idSeq.next(preferEncryption);

    if (preferEncryption && msgsToAck.isNotEmpty) {
      final ack = _idSeq.next(false);
      final ackMsg = MsgsAck(msgIds: msgsToAck.toList());
      msgsToAck.clear();

      final container = MsgContainer(
        messages: [
          Msg(
            msgId: m.id,
            seqno: m.seqno,
            bytes: 0,
            body: method,
          ),
          Msg(
            msgId: ack.id,
            seqno: ack.seqno,
            bytes: 0,
            body: ackMsg,
          )
        ],
      );

      void nop(TlObject o) {
        //
      }

      nop(container);

      //return send(container, false);
    }

    _pending[m.id] = completer;
    final buffer = authorizationKey.id == 0
        ? _encodeNoAuth(method, m)
        : _encodeWithAuth(method, m, 10, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));

    return completer.future;
  }
}
