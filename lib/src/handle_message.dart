import 'dart:async';

import 'package:archive/archive.dart';
import 'package:meta/meta.dart';
import 'package:nop/nop.dart' as l;
import 'package:tg_api/api.dart';
import 'package:tg_api/tg_api.dart';

import 'encoders.dart';
import 'frame.dart';

mixin HandleMessageMixin {
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
          _removeAndCreateNew(msg.badMsgId);

        case BadServerSalt salt:
          updateSalt(salt.newServerSalt);
          _removeAndCreateNew(msg.badMsgId);

        case RpcResult():
          final result = msg.result;
          switch (result) {
            case RpcError():
              _complete(Result.error(result), msg.reqMsgId);
            case GzipPacked():
              final gZippedData =
                  const GZipDecoder().decodeBytes(result.packedData);
              final newObj = BinaryReader(gZippedData).readObject();
              final newRpcResult =
                  RpcResult(reqMsgId: msg.reqMsgId, result: newObj);
              _handleIncomingMessage(newRpcResult);
            case _:
              _complete(Result.ok(msg.result), msg.reqMsgId);
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

  final _idSeq = MessageIdSequenceGenerator();

  void updateSeqno(int newSeqno) {
    _idSeq.updateSeqno(newSeqno);
  }

  bool get preferEncryption;

  IdSeq get nextTaskId => _idSeq.next(preferEncryption);

  final _tasks = <Object, MtTask>{};

  MtTask? getTask(Object id) => _tasks[id];

  void _remove(int id) => _tasks.remove(id);

  void send(MtTask task);

  Object getKey(MtTask task) {
    return task.idSeq.id;
  }

  MtTask createTask(TlMethod method) {
    final task = MtTask(nextTaskId, method, _remove);
    _tasks[getKey(task)] = task;
    send(task);
    return task;
  }

  void _removeAndCreateNew(int? id) {
    final oldTask = _tasks.remove(id);
    if (oldTask != null) {
      final newTask = oldTask._copy(nextTaskId);
      _tasks[newTask.idSeq.id] = newTask;
      send(newTask);
      return;
    }
  }

  void complete(Result result, Object id) {
    _complete(result, id);
  }

  void _complete(Result result, Object id) {
    final task = getTask(id);
    if (task == null) {
      l.Log.w('task == null, $id');
    }
    task?._complete(result);
  }

  @mustCallSuper
  void close() {
    _streamController.close();
  }
}

final class MtTask {
  MtTask(this.idSeq, this.method, this._remove, [Completer<Result>? c])
      : _completer = c ?? Completer<Result>();
  final IdSeq idSeq;
  final TlMethod method;
  final void Function(int id) _remove;

  final Completer<Result> _completer;

  MtTask _copy(IdSeq newIdSeq) {
    return MtTask(newIdSeq, method, _remove, _completer);
  }

  Future<Result> get future => _completer.future;

  void _complete(Result value) {
    _remove(idSeq.id);
    _completer.complete(value);
  }
}
