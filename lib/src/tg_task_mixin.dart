import 'dart:async';

import 'package:nop/nop.dart' as l;
import 'package:tg_api/tg_api.dart';

import 'encoders.dart';

mixin TgTaskMixin {
  final _idSeq = MessageIdSequenceGenerator();

  void updateSeqno(int newSeqno) {
    _idSeq.updateSeqno(newSeqno);
  }

  bool get preferEncryption;

  IdSeq get nextTaskId => _idSeq.next(preferEncryption);

  final _tasks = <Object, MtTask>{};

  void send(MtTask task);

  Object getKey(MtTask task) {
    return task.idSeq.id;
  }

  MtTask createTask(TlMethod method) {
    final task = MtTask(nextTaskId, method);
    _tasks[getKey(task)] = task;
    send(task);
    return task;
  }

  void removeAndCreateNew(int? id) {
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
    final task = _tasks.remove(id);
    if (task == null) {
      l.Log.w('task == null, $id');
    }
    task?._complete(result);
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
}
