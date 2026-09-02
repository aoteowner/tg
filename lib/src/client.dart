import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'package:archive/archive.dart';
import 'package:nop/nop.dart' as nop;
import 'package:tg_api/account.dart';
import 'package:tg_api/api.dart';
import 'package:tg_api/auth.dart';
import 'package:tg_api/help.dart';

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
  int dcId,
) {
  return AuthKeyClient(sender, receiver, obfuscation).exchangeAndClosed(dcId);
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

  void upateAuthKey(AuthorizationKey key, Obfuscation obfuscation) {
    _sub?.cancel();
    _transformer?.dispose();
    final t = _transformer = BaseTransformer(obfuscation, key.key);
    _sub = t.stream.listen(listener, onError: onError, onDone: onDone);
    _key = key;
  }

  void onError(dynamic error, dynamic stack) {
    tgTask.reconnect(error, stack);
  }

  void onDone() {
    nop.Log.w('messageReciver done.');
  }

  @override
  void updateSalt(int newSalt) {
    _key?.salt = newSalt;
  }
}

/// 发送
final class AuthKeyData {
  AuthKeyData();
  AuthorizationKey? _key;
  Obfuscation? _obfuscation;

  AuthorizationKey? get key => _key;
  Obfuscation get obfuscation => _obfuscation!;

  void updateAuthKey(AuthorizationKey? authKey) {
    _key = authKey;
  }

  void updateObf(int dcId) {
    _obfuscation = Obfuscation.random(false, dcId);
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

final class MessageIo with Messager implements TgTaskBase {
  MessageIo._(
    this._keyData,
    this.apiId,
    this.appVersion,
    this.langCode,
    this.onReceive,
    this.onReconnect,
  );
  late final TgTask tgTask = TgTask(this);

  final AuthKeyData _keyData;
  late final receiver = MessageReceiver(tgTask: this);
  final int apiId;
  DcOption? dcOption;

  AuthorizationKey? get key => _keyData.key;

  Uint8List encrypt(TlObject obj, IdSeq idSeq, int sessionId) {
    return _keyData.encrypt(obj, idSeq, sessionId);
  }

  factory MessageIo({
    required int apiId,
    required String appVersion,
    required String? langCode,
    required void Function() onReconnect,
    required void Function(TlObject) onReceive,
  }) {
    return MessageIo._(
      AuthKeyData(),
      apiId,
      appVersion,
      langCode,
      onReceive,
      onReconnect,
    );
  }
  Socket? _socket;
  Future<void> connect(Socket socket, DcOption dcOption) async {
    _keyData.updateObf(dcOption.id);
    _socket = null;
    final obf = _keyData.obfuscation;
    newSessionId();

    socket.add(obf.preamble);
    final receiver = socket.asBroadcastStream();
    final key =
        _keyData.key ?? await getTgAuthKey(receiver, socket, obf, dcOption.id);
    _socket = socket;

    _init = false;
    update(key);
    receiver.listen(
      onData,
      onDone: () {
        if (_socket == socket) {
          _socket = null;
        }
      },
    );
  }

  void onData(Uint8List data) {
    receiver._transformer?.readFrame(data);
  }

  final void Function() onReconnect;
  void update(AuthorizationKey key) {
    receiver.upateAuthKey(key, _keyData.obfuscation);
    _keyData.updateAuthKey(key);
    tgTask.resend();
  }

  void updateAuthKey(AuthorizationKey? key) {
    _keyData.updateAuthKey(key);
  }

  static final rng = Random();

  static int generateSessionId() => rng.nextInt(1 << 31);

  /// Telegram session
  var _tgTempSession = generateSessionId();

  var _init = false;
  @override
  void send(MtTask task) {
    final socket = _socket;
    if (socket != null) {
      final inited = _init == true;
      _init = true;
      socket.add(
        encrypt(wrapInLayer(task.method, inited), task.idSeq, _tgTempSession),
      );
    }
  }

  final String? langCode;
  final String appVersion;
  TlMethod wrapInLayer(TlMethod method, bool inited) {
    if (!inited) {
      method = InitConnectionMethod(
        apiId: apiId,
        deviceModel: Platform.localHostname,
        systemVersion: Platform.operatingSystem,
        appVersion: '${Platform.operatingSystem} $appVersion',
        systemLangCode: langCode ?? 'en',
        langPack: '',
        langCode: langCode ?? 'en',
        query: method,
      );
    }

    switch (method) {
      case GetConfigMethod():
      case GetCdnConfigMethod():
      case ExportAuthorizationMethod():
      case ImportAuthorizationMethod():
      case InitConnectionMethod():
      case RegisterDeviceMethod():
        return InvokeWithLayerMethod(layer: layer, query: method);
    }

    return method;
  }

  void close() {
    receiver.close();
    tgTask.close();
  }

  @override
  void complete(Result<TlObject> result, Object id) {
    tgTask.complete(result, id);
  }

  final void Function(TlObject data) onReceive;
  @override
  void onReceiverData(TlObject data) {
    onReceive.call(data);
  }

  @override
  void removeAndCreateNew(int? id) {
    tgTask.removeAndCreateNew(id);
  }

  @override
  void reconnect(Object? error, stack) {
    nop.Log.e('$error\n$stack');
    onReconnect();
  }

  void newSessionId() {
    _tgTempSession = generateSessionId();
    tgTask.idSeq.resetSeqno(0);
  }
}

abstract mixin class TgTaskBase {
  void removeAndCreateNew(int? id);
  void complete(Result result, Object id);

  void onReceiverData(TlObject data);

  void reconnect(Object? error, dynamic stack);
}

mixin HandleMessageMixin {
  TgTaskBase get tgTask;

  void updateSalt(int newSalt);

  void listener(Frame frame) {
    _handleIncomingMessage(frame.message);
  }

  void _handleIncomingMessage(TlObject msg) {
    switch (msg) {
      case MessageHash():
        _handleIncomingMessage(msg.body);
      case MessageContainer():
        for (final message in msg.messages) {
          _handleIncomingMessage(message);
        }

      case BadServerSaltHashedab447b salt:
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
        final gZippedData = const GZipDecoder().decodeBytes(msg.packedData);
        final newObj = BinaryReader(gZippedData).readObject();
        _handleIncomingMessage(newObj);
      case var v:
        tgTask.onReceiverData(v);
    }
  }
}
