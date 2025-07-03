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

Future<AuthorizationKey> getTgAuthKey(Stream<Uint8List> receiver,
    Sink<List<int>> sender, Obfuscation obfuscation) {
  return AuthKeyClient(sender, receiver, obfuscation).exchangeAndClosed();
}

/// 接收
class MessageReceiver with HandleMessageMixin {
  MessageReceiver({
    required this.tgTask,
    required this.sink,
    required this.sink2,
  });

  void onData(Uint8List data) {
    _transformer?.readFrame(data);
  }

  StreamSubscription? _sub;

  @override
  final Sink<UpdatesBase> sink;
  @override
  final Sink<TlObject> sink2;

  void close() {
    _sub?.cancel();
    _transformer?.dispose();
  }

  @override
  final TgTaskBase tgTask;
  AuthorizationKey? _key;
  BaseTransformer? _transformer;

  void updateTransformer(AuthorizationKey key, Obfuscation obfuscation) {
    _sub?.cancel();
    _transformer?.dispose();
    final t = _transformer = BaseTransformer(obfuscation, key.key);
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

  void updateAuthKey(AuthorizationKey authKey) {
    _key = authKey;
  }

  void updateObf() {
    _obfuscation = Obfuscation.random(false, id);
  }

  Uint8List encrypt(MtTask task) {
    if (key case var key?) {
      final buffer = encodeWithAuth(task.method, task.idSeq, 10, key);

      obfuscation.send.encryptDecrypt(buffer, buffer.length);
      return buffer;
    }

    final buffer = encodeNoAuth(task.method, task.idSeq);
    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    return buffer;
  }
}

final class MessageIo with Messager, TgTaskBase {
  MessageIo._(this.data);
  late final TgTask tgTask = TgTask(this);

  final AuthKeyData data;
  late final receiver = MessageReceiver(
    tgTask: this,
    sink: _controller,
    sink2: _controller2,
  );

  Sink<List<int>>? _sender;

  final _controller = StreamController<UpdatesBase>.broadcast();
  final _controller2 = StreamController<TlObject>.broadcast();

  Stream<UpdatesBase> get stream => _controller.stream;

  Stream<TlObject> get streamObj => _controller2.stream;

  factory MessageIo(AuthorizationKey? key, int id) {
    return MessageIo._(AuthKeyData(key, id));
  }

  void onData(Uint8List data) {
    receiver.onData(data);
  }

  void update(Sink<List<int>> sender, AuthorizationKey key) {
    _sender = sender;
    receiver.updateTransformer(key, data.obfuscation);
    data.updateAuthKey(key);

    if (_taskCache.isNotEmpty) {
      final local = List.of(_taskCache);
      _taskCache.clear();
      for (var task in local) {
        sender.add(data.encrypt(task));
      }
    }
  }

  void disconnect() {
    _sender = null;
  }

  final List<MtTask> _taskCache = [];
  @override
  void send(MtTask task) {
    if (_sender case var sender?) {
      sender.add(data.encrypt(task));
    } else {
      _taskCache.add(task);
    }
  }

  @override
  void complete(Result<TlObject> result, Object id) {
    tgTask.complete(result, id);
  }

  @override
  void removeAndCreateNew(int? id) {
    tgTask.removeAndCreateNew(id);
  }

  @override
  void updateSeqno(int newSeqno) {
    tgTask.updateSeqno(newSeqno);
  }

  void close() {
    receiver.close();
    _controller.close();
    _controller2.close();
  }
}

abstract mixin class TgTaskBase {
  void removeAndCreateNew(int? id);
  void complete(Result result, Object id);
  void updateSeqno(int newSeqno);
}

mixin HandleMessageMixin {
  TgTaskBase get tgTask;
  Sink<UpdatesBase> get sink;
  Sink<TlObject> get sink2;
  void updateSeqno(int newSeqno) {
    tgTask.updateSeqno(newSeqno);
  }

  void updateSalt(int newSalt);

  int? _seqno;
  void listener(Frame frame) {
    _seqno = frame.seqno;
    _handleIncomingMessage(frame.message);
  }

  void _handleIncomingMessage(TlObject msg) {
    switch (msg) {
      case UpdatesBase():
        sink.add(msg);
      case Message():
        _handleIncomingMessage(msg.body);
      case MsgContainer():
        for (final message in msg.messages) {
          _handleIncomingMessage(message);
        }

      case BadMsgNotification():
        if (_seqno case var no?) updateSeqno(no);
        tgTask.removeAndCreateNew(msg.badMsgId);

      case BadServerSalt salt:
        updateSalt(salt.newServerSalt);
        tgTask.removeAndCreateNew(msg.badMsgId);

      case RpcResult():
        final result = msg.result;
        switch (result) {
          case RpcError():
            tgTask.complete(Result.error(result), msg.reqMsgId);
          case GzipPacked():
            final gZippedData =
                const GZipDecoder().decodeBytes(result.packedData);
            final newObj = BinaryReader(gZippedData).readObject();
            final newRpcResult =
                RpcResult(reqMsgId: msg.reqMsgId, result: newObj);
            _handleIncomingMessage(newRpcResult);
          case _:
            tgTask.complete(Result.ok(msg.result), msg.reqMsgId);
        }

      case GzipPacked():
        final gZippedData = GZipDecoder().decodeBytes(msg.packedData);
        final newObj = BinaryReader(gZippedData).readObject();
        _handleIncomingMessage(newObj);
      case var v:
        sink2.add(v);
    }
  }
}
