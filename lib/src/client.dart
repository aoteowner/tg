part of '../tg.dart';

class Client extends ApiClient with HandleMessageMixin {
  Client({
    required this.receiver,
    required this.sender,
    required this.obfuscation,
    required this.authorizationKey,
  }) {
    _transformer = _BaseTransformer(
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
    final uot = _BaseTransformer.unEncrypted(
      receiver,
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

  final _idSeq = _MessageIdSequenceGenerator();

  @override
  void updateSalt(int newSalt) {
    authorizationKey.salt = newSalt;
  }

  @override
  void updateSeqno(int newSeqno) {
    _idSeq._seqno = newSeqno;
  }

  @override
  IdSeq get nextTaskId {
    final preferEncryption = authorizationKey.id != 0;
    return _idSeq.next(preferEncryption);
  }

  @override
  void send(MtTask task) {
    final buffer = authorizationKey.id == 0
        ? _encodeNoAuth(task.method, task.idSeq)
        : _encodeWithAuth(task.method, task.idSeq, 10, authorizationKey);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));
  }

  @override
  Future<Result<TlObject>> invoke(TlMethod method) => createTask(method).future;
}
