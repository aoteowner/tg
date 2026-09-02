import 'dart:async';

import 'package:tg_api/api.dart';

import 'encoders.dart';

final class TgTask {
  TgTask(this.messager);
  final Messager messager;
  final idSeq = MessageIdSequenceGenerator();

  IdSeq get nextTaskId => idSeq.next(messager.preferEncryption);

  final _tasks = <Object, MtTask>{};

  Object getKey(MtTask task) {
    return messager.getKey(task);
  }

  MtTask createTask(TlMethod method) {
    final task = MtTask(nextTaskId, method);
    _tasks[getKey(task)] = task;
    messager.send(task);
    return task;
  }

  void removeAndCreateNew(Object? id) {
    final oldTask = _tasks.remove(id);
    if (oldTask != null) {
      final newTask = oldTask._copy(nextTaskId);
      _tasks[getKey(newTask)] = newTask;
      messager.send(newTask);
    }
  }

  void resend() {
    final list = _tasks.keys.toList();
    for (var id in list) {
      removeAndCreateNew(id);
    }
  }

  bool complete(Result result, Object id) {
    final task = _tasks.remove(id);

    task?._complete(result);
    return task != null;
  }

  void close() {
    final local = Map.of(_tasks);
    _tasks.clear();
    for (var entry in local.entries) {
      entry.value._complete(
        Result.error(RpcError(errorCode: -1, errorMessage: 'closed')),
      );
    }
  }
}

final class MtTask {
  MtTask(this.idSeq, this.method, [Completer<Result>? c])
    : _completer = c ?? Completer<Result>();
  final IdSeq idSeq;
  final TlMethod method;

  final Completer<Result> _completer;

  MtTask _copy(IdSeq newIdSeq) {
    return MtTask(newIdSeq, method, _completer);
  }

  Future<Result> get future => _completer.future;

  void _complete(Result value) {
    _completer.complete(value);
  }

  void completeError() {
    if (_completer.isCompleted) return;
    _completer.complete(
      Result.error(RpcError(errorCode: -1, errorMessage: 'removed.')),
    );
  }

  void complete(TlObject value) {
    if (_completer.isCompleted) return;
    _completer.complete(Result.ok(value));
  }
}

abstract mixin class Messager {
  Object getKey(MtTask task) {
    return task.idSeq.id;
  }

  bool get preferEncryption => true;

  void send(MtTask task) {}
}
