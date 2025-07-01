import 'dart:typed_data';

import 'package:tg_api/api.dart';
import 'package:tg_api/tg_api.dart';
import 'auth_key.dart';
import 'decoders.dart';
import 'diffie_hellman.dart';
import 'handle_message.dart';
import 'encoders.dart';
import 'obfuscation.dart';

class Client extends ApiClient with HandleMessageMixin {
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

    _transformer.stream.listen(listener);
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
    final buffer = preferEncryption
        ? encodeNoAuth(task.method, task.idSeq)
        : encodeWithAuth(task.method, task.idSeq, 10, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));
  }

  @override
  Future<Result<TlObject>> invoke(TlMethod method) => createTask(method).future;
}

mixin MtDhClientMixin on HandleMessageMixin {}
