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

/// 接收
class MessageReceiver with HandleMessageMixin {
  MessageReceiver({
    required Stream<Uint8List> receiver,
    required this.data,
    required this.tgTask,
    required this.sink,
    required this.sink2,
  }) {
    _transformer = BaseTransformer(
      receiver,
      data.obfuscation,
      data.key.key,
    );

    _sub = _transformer.stream.listen(listener);
  }

  late StreamSubscription _sub;

  @override
  final Sink<UpdatesBase> sink;
  @override
  final Sink<TlObject> sink2;

  void close() {
    _sub.cancel();
    _transformer.dispose();
  }

  @override
  final TgTaskBase tgTask;
  final AuthKeyData data;
  late final BaseTransformer _transformer;

  @override
  void updateSalt(int newSalt) {
    data.key.salt = newSalt;
  }
}

/// 发送
final class AuthKeyData {
  AuthKeyData(this.key, this.id, Obfuscation? obfuscation)
      : obfuscation = obfuscation ?? Obfuscation.random(false, id);
  final AuthorizationKey key;
  Obfuscation obfuscation;
  final int id;

  void updateObf() {
    obfuscation = Obfuscation.random(false, id);
  }

  Uint8List encrypt(MtTask task) {
    final buffer = encodeWithAuth(task.method, task.idSeq, 10, key);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    return buffer;
  }
}

final class MessageIo with Messager, TgTaskBase {
  MessageIo._(this.data);
  late final TgTask tgTask = TgTask(this);
  final AuthKeyData data;

  MessageReceiver? _receiver;
  Sink<List<int>>? _sender;

  final _controller = StreamController<UpdatesBase>.broadcast();
  final _controller2 = StreamController<TlObject>.broadcast();

  Stream<UpdatesBase> get stream => _controller.stream;

  Stream<TlObject> get streamObj => _controller2.stream;

  factory MessageIo(AuthorizationKey key, int id, {Obfuscation? obfuscation}) {
    final data = AuthKeyData(key, id, obfuscation);
    return MessageIo._(data);
  }

  void update(Stream<Uint8List> receiver, Sink<List<int>> sender) {
    _receiver?.close();
    _receiver = MessageReceiver(
      receiver: receiver,
      data: data,
      tgTask: this,
      sink: _controller,
      sink2: _controller2,
    );

    _sender = sender;

    if (_taskCache.isNotEmpty) {
      final local = List.of(_taskCache);
      _taskCache.clear();
      for (var task in local) {
        sender.add(data.encrypt(task));
      }
    }
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
    _receiver?.close();
    _receiver = null;
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
