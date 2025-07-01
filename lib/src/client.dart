import 'dart:async';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:meta/meta.dart';
import 'package:nop/nop.dart' as l;
import 'package:tg_api/api.dart';
import 'package:tg_api/tg_api.dart';

import 'auth_key.dart';
import 'decoders.dart';
import 'diffie_hellman.dart';
import 'encoders.dart';
import 'frame.dart';
import 'obfuscation.dart';
import 'tg_task_mixin.dart';

class Client extends ApiClient with TgTaskMixin, HandleMessageMixin {
  Client({
    required this.receiver,
    required this.sender,
    required this.obfuscation,
    required this.authorizationKey,
  }) {
    _transformer = BaseTransformer(
      receiver,
      obfuscation,
      authorizationKey.key,
    );

    _sub = _transformer.stream.listen(listener);
  }

  late StreamSubscription _sub;

  @override
  void close() {
    _sub.cancel();
    _transformer.dispose();
    super.close();
  }

  static Future<AuthorizationKey> authorize(
    Stream<Uint8List> receiver,
    Sink<List<int>> sender,
    Obfuscation obfuscation,
  ) async {
    final dh = AuthKeyClient(
      sender,
      receiver,
      obfuscation,
    );
    final ak = await dh.exchange();
    dh.close();
    return ak;
  }

  void start() {
    sender.add(obfuscation.preamble);
  }

  final AuthorizationKey authorizationKey;
  final Obfuscation obfuscation;
  final Stream<Uint8List> receiver;
  final Sink<List<int>> sender;

  late final BaseTransformer _transformer;

  @override
  void updateSalt(int newSalt) {
    authorizationKey.salt = newSalt;
  }

  @override
  bool get preferEncryption => authorizationKey.id != 0;

  @override
  void send(MtTask task) {
    final buffer = !preferEncryption
        ? encodeNoAuth(task.method, task.idSeq)
        : encodeWithAuth(task.method, task.idSeq, 10, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));
  }

  @override
  Future<Result<TlObject>> invoke(TlMethod method) => createTask(method).future;
}

mixin HandleMessageMixin on TgTaskMixin {
  final _streamController = StreamController<UpdatesBase>.broadcast();

  Stream<UpdatesBase> get stream => _streamController.stream;

  void updateSalt(int newSalt) {}

  int? _seqno;
  void listener(Frame frame) {
    _seqno = frame.seqno;
    frame.messageId;
    _handleIncomingMessage(frame.message, p: false);
  }

  void _handleIncomingMessage(TlObject msg, {bool p = true}) {
    try {
      if (p) {
        l.Log.e('...$p');
      }
      switch (msg) {
        case UpdatesBase():
          _streamController.add(msg);
        case Message():
          _handleIncomingMessage(msg.body);
        case MsgContainer():
          for (final message in msg.messages) {
            _handleIncomingMessage(message);
          }

        case BadMsgNotification():
          if (_seqno case var no?) updateSeqno(no);
          removeAndCreateNew(msg.badMsgId);

        case BadServerSalt salt:
          updateSalt(salt.newServerSalt);
          removeAndCreateNew(msg.badMsgId);

        case RpcResult():
          final result = msg.result;
          switch (result) {
            case RpcError():
              complete(Result.error(result), msg.reqMsgId);
            case GzipPacked():
              final gZippedData =
                  const GZipDecoder().decodeBytes(result.packedData);
              final newObj = BinaryReader(gZippedData).readObject();
              final newRpcResult =
                  RpcResult(reqMsgId: msg.reqMsgId, result: newObj);
              _handleIncomingMessage(newRpcResult);
            case _:
              complete(Result.ok(msg.result), msg.reqMsgId);
          }

        case GzipPacked():
          final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
          final newObj = BinaryReader(gZippedData).readObject();
          _handleIncomingMessage(newObj);
      }
    } catch (e, s) {
      l.Log.e('$e\n$s');
    }
  }

  @mustCallSuper
  void close() {
    _streamController.close();
  }
}
