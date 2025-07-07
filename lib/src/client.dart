import 'dart:async';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:tg_api/api.dart';
import 'package:tg_api/tg_api.dart';

import 'auth_key.dart';
import 'decoders.dart';
import 'diffie_hellman.dart';
import 'encoders.dart';
import 'frame.dart';
import 'obfuscation.dart';
import 'tg_task_mixin.dart';

Future<AuthorizationKey> getTgAuthKey(
  Stream<Uint8List> receiver,
  Sink<List<int>> sender,
  Obfuscation obfuscation,
) {
  return AuthKeyClient(sender, receiver, obfuscation).exchangeAndClosed();
}

/// 接收
class MessageReceiver with HandleMessageMixin {
  MessageReceiver({required this.tgTask});

  StreamSubscription? _sub;

  void close() {
    _sub?.cancel();
    _transformer?.dispose();
  }

  @override
  final TgTaskBase tgTask;
  AuthorizationKey? _key;
  BaseTransformer? _transformer;

  void upateAuthKey(
    AuthorizationKey key,
    Obfuscation obfuscation,
    void Function()? onReconnect,
  ) {
    _sub?.cancel();
    _transformer?.dispose();
    final t = _transformer = BaseTransformer(obfuscation, key.key)
      ..reConnect = onReconnect;
    _sub = t.stream.listen(listener);
    _key = key;
  }

  @override
  void updateSalt(int newSalt) {
    _key?.salt = newSalt;
  }
}

/// 发送
final class AuthKeyData {
  AuthKeyData(this._key, this.id)
    : _obfuscation = Obfuscation.random(false, id);
  AuthorizationKey? _key;
  Obfuscation _obfuscation;

  AuthorizationKey? get key => _key;
  Obfuscation get obfuscation => _obfuscation;
  final int id;

  void updateAuthKey(AuthorizationKey? authKey) {
    _key = authKey;
  }

  void updateObf() {
    _obfuscation = Obfuscation.random(false, id);
  }

  Uint8List encrypt(TlObject obj, IdSeq idSeq, int sessionId) {
    if (key case var key?) {
      final buffer = encodeWithAuth(obj, idSeq, sessionId, key);

      obfuscation.send.encryptDecrypt(buffer, buffer.length);
      return buffer;
    }
    return sendBase(obj, idSeq);
  }

  Uint8List sendBase(TlObject obj, IdSeq idSeq) {
    final buffer = encodeNoAuth(obj, idSeq);
    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    return buffer;
  }
}

final class MessageIo with Messager {
  MessageIo._(this.data, this.base) : receiver = MessageReceiver(tgTask: base);
  late final TgTask tgTask = TgTask(this);

  final TgTaskBase base;
  final AuthKeyData data;
  final MessageReceiver receiver;

  factory MessageIo(AuthorizationKey? key, int id, TgTaskBase base) {
    return MessageIo._(AuthKeyData(key, id), base);
  }

  void onData(Uint8List data) {
    receiver._transformer?.readFrame(data);
  }

  void Function()? onReconnect;
  void update(AuthorizationKey key) {
    receiver.upateAuthKey(key, data.obfuscation, onReconnect);
    data.updateAuthKey(key);
    tgTask.resend();
  }

  void Function(MtTask task)? onSend;
  @override
  void send(MtTask task) {
    onSend?.call(task);
  }

  void close() {
    receiver.close();
    tgTask.close();
  }
}

abstract mixin class TgTaskBase {
  void removeAndCreateNew(int? id);
  void complete(Result result, Object id);

  void onNewSessionCreated(NewSessionCreated session);

  void onReceiverData(TlObject data);
}

mixin HandleMessageMixin {
  TgTaskBase get tgTask;

  void updateSalt(int newSalt);

  void listener(Frame frame) {
    _handleIncomingMessage(frame.message);
  }

  void _handleIncomingMessage(TlObject msg) {
    switch (msg) {
      case Pong():
        tgTask.complete(Result.ok(msg), msg.msgId);
      case Message():
        _handleIncomingMessage(msg.body);
      case MsgContainer():
        for (final message in msg.messages) {
          _handleIncomingMessage(message);
        }

      case BadServerSalt salt:
        updateSalt(salt.newServerSalt);
        tgTask.removeAndCreateNew(msg.badMsgId);

      case RpcResult():
        final result = msg.result;
        switch (result) {
          case RpcError():
            tgTask.complete(Result.error(result), msg.reqMsgId);
          case GzipPacked():
            final gZippedData = const GZipDecoder().decodeBytes(
              result.packedData,
            );
            final newObj = BinaryReader(gZippedData).readObject();
            final newRpcResult = RpcResult(
              reqMsgId: msg.reqMsgId,
              result: newObj,
            );
            _handleIncomingMessage(newRpcResult);
          case _:
            tgTask.complete(Result.ok(msg.result), msg.reqMsgId);
        }

      case GzipPacked():
        final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
        final newObj = BinaryReader(gZippedData).readObject();
        _handleIncomingMessage(newObj);
      case var v:
        tgTask.onReceiverData(v);
    }
  }
}
