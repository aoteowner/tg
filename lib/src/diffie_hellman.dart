import 'dart:async';
import 'dart:typed_data';

import 'package:nop/nop.dart' as l;
import 'package:tg/src/extensions.dart';
import 'package:tg/tg.dart';
import 'package:tg_api/api.dart';
import 'package:tg_api/tg_api.dart';

import 'crypto.dart';
import 'encoders.dart';
import 'frame.dart';
import 'private.dart';
import 'public_keys.dart';

class AuthKeyClient extends ApiClient with Messager {
  AuthKeyClient._(this.sender, this.obfuscation);

  factory AuthKeyClient(Sink<List<int>> sender, Stream<Uint8List> receiver,
      Obfuscation obfuscation) {
    final client = AuthKeyClient._(sender, obfuscation);
    client.init(receiver);
    return client;
  }

  late StreamSubscription _sub;
  late BaseTransformer _uot;

  void init(Stream<Uint8List> receiver) {
    _uot = BaseTransformer.unEncrypted(
      receiver,
      obfuscation,
    );

    _sub = _uot.stream.listen(_onMessage);
  }

  void close() {
    _sub.cancel();
    _uot.dispose();
  }

  final Obfuscation obfuscation;
  final Sink<List<int>> sender;

  void _onMessage(Frame frame) {
    final msg = frame.message;

    switch (msg) {
      case ResPQ():
        final key = msg.nonce.toString();
        tgTask.complete(Result.ok(msg), key);
      case ServerDHParamsOk():
        final key = '${msg.nonce}-${msg.serverNonce}';
        tgTask.complete(Result.ok(msg), key);
      case DhGenOk():
        final key = '${msg.nonce}-${msg.serverNonce}';
        tgTask.complete(Result.ok(msg), key);
      case DhGenRetry():
        final key = '${msg.nonce}-${msg.serverNonce}';
        tgTask.complete(Result.ok(msg), key);
      case DhGenFail():
        final key = '${msg.nonce}-${msg.serverNonce}';
        tgTask.complete(Result.ok(msg), key);
    }
  }

  Future<ResPQ> _reqPqMulti([Int128? nonce]) async {
    final res = await reqPqMulti(nonce: nonce ?? Int128.random());
    return res.result!;
  }

  Future<ServerDHParamsOk> _reqDHParams(
    ResPQ resPQ,
    Int256 newNonce, {
    int? dc,
  }) async {
    final fingerprint = resPQ.serverPublicKeyFingerprints
        .firstWhere((x) => rsaKeys[x] != null, orElse: () => 0);

    final publicKey = rsaKeys[fingerprint]!;
    // final n = _bigEndianInteger(publicKey.n);
    // final e = _bigEndianInteger(publicKey.e);
    final RRSaKey(:n, :e) = publicKey;

    final pq = resPQ.pq.buffer.asByteData().getUint64(0, Endian.big);
    final p = pqFactorize(pq);
    final q = pq ~/ p;

    final pqInnerData = PQInnerDataDc(
      pq: resPQ.pq,
      p: int64ToBigEndian(p),
      q: int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      newNonce: newNonce,
      dc: dc ?? 0,
    );

    Uint8List? encryptedData;
    do {
      final clearBuffer = Uint8List(256);

      final aesKey = Uint8List(32);
      final zeroIV = Uint8List(32);

      rng.getBytes(aesKey);
      clearBuffer.setRange(0, 32, aesKey);

      final msg = pqInnerData.asUint8List();
      clearBuffer.setRange(32, 32 + msg.length, msg);

      // length before padding
      final clearLength = msg.length;

      rng.getBytes(
        clearBuffer,
        clearLength + 32,
        192 - clearLength,
      );

      final hash = sha256(clearBuffer.take(192 + 32).toList());
      clearBuffer.setRange(192 + 32, 192 + 32 + hash.length, hash);
      clearBuffer.reverse(32, 192);

      final aesEncrypted = aesIgeEncryptDecrypt(
        Uint8List.fromList(clearBuffer.skip(32).take(224).toList()),
        AesKeyIV(aesKey, zeroIV),
        true,
      );

      final hashAes = sha256(aesEncrypted);

      for (int i = 0; i < 32; i++) // prefix aes_encrypted with temp_key_xor
      {
        clearBuffer[i] = (aesKey[i] ^ hashAes[i]) % 256;
      }

      clearBuffer.setRange(32, 256, aesEncrypted);

      final x = bigEndianInteger(clearBuffer);

      if (x < n) // if good result, encrypt with RSA key:
      {
        final mp = x.modPow(e, n);
        encryptedData = mp.toBytes(Endian.big);
      }
    } while (encryptedData == null);

    final res = await reqDHParams(
      p: int64ToBigEndian(p),
      q: int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      encryptedData: encryptedData,
      publicKeyFingerprint: fingerprint,
    );

    return res.result as ServerDHParamsOk;
  }

  Future<SetClientDHParamsAnswer> _setClientDHParams(
    ResPQ resPQ,
    BigInt gB,
    int retryId,
    AesKeyIV keys,
  ) async {
    final clientDHinnerData = ClientDHInnerData(
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      retryId: retryId,
      gB: gB.toBytes(Endian.big),
    );

    final messageBuffer = clientDHinnerData.asUint8List();
    final totalLength = messageBuffer.length + 20;
    final paddingToAdd = (0x7FFFFFF0 - totalLength) % 16;
    final padding = Uint8List(paddingToAdd);
    rng.getBytes(padding);

    final messageHash = sha1(messageBuffer);

    final clearStream = [...messageHash, ...messageBuffer, ...padding];
    final encryptedData = aesIgeEncryptDecrypt(
      Uint8List.fromList(clearStream),
      keys,
      true,
    );

    final res = await setClientDHParams(
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      encryptedData: encryptedData,
    );

    return res.result!;
  }

  Future<AuthorizationKey> _createAuthKey(
    ResPQ resPQ,
    ServerDHParamsOk serverDHparams,
    Int256 newNonce, {
    int? dc,
  }) async {
    final pq = resPQ.pq.buffer.asByteData().getUint64(0, Endian.big);
    final p = pqFactorize(pq);
    final q = pq ~/ p;

    final pqInnerData = PQInnerDataDc(
      pq: resPQ.pq,
      p: int64ToBigEndian(p),
      q: int64ToBigEndian(q),
      nonce: resPQ.nonce,
      serverNonce: resPQ.serverNonce,
      newNonce: newNonce,
      dc: dc ?? 0,
    );

    final keys = constructTmpAESKeyIV(resPQ.serverNonce, pqInnerData.newNonce);
    final answer = aesIgeEncryptDecrypt(
      serverDHparams.encryptedAnswer,
      keys,
      false,
    );

    final answerReader = BinaryReader(answer);
    final answerHash = answerReader.readRawBytes(20);
    final answerObj = answerReader.readObject();

    if (answerObj is! ServerDHInnerData) {
      throw Exception('ServerDHInnerData expected.');
    }

    final paddingLength = answer.length - answerReader.position;
    final hash =
        sha1(answer.skip(20).take(answer.length - paddingLength - 20).toList());

    print('${hexToStr(answerHash)} == ${hexToStr(hash)}');

    final gA = bigEndianInteger(answerObj.gA);
    final dhPrime = bigEndianInteger(answerObj.dhPrime);

    checkGoodPrime(dhPrime, answerObj.g);

    final salt = Uint8List(256);
    rng.getBytes(salt);
    final b = bigEndianInteger(salt);

    final gB = BigInt.from(answerObj.g).modPow(b, dhPrime);
    checkGoodGaAndGb(gA, dhPrime);
    checkGoodGaAndGb(gB, dhPrime);

    var retryId = 0;
    final setClientDHparamsAnswer = await _setClientDHParams(
      resPQ,
      gB,
      retryId,
      keys,
    );

    //7)
    final gab = gA.modPow(b, dhPrime);
    final authKey = gab.toBytes(Endian.big);
    //8)
    final authKeyHash = sha1(authKey);
    // (auth_key_aux_hash)
    retryId = BinaryReader(Uint8List.fromList(authKeyHash)).readInt64(false);
    //9)
    // if (setClientDHparamsAnswer is not DhGenOk dhGenOk) throw new WTException("not dh_gen_ok");
    // if (dhGenOk.nonce != nonce) throw new WTException("Nonce mismatch");
    // if (dhGenOk.server_nonce != resPQ.server_nonce) throw new WTException("Server Nonce mismatch");

    final expectedNewNonceN = [
      ...pqInnerData.newNonce.data,
      1,
      ...authKeyHash.take(8),
    ];

    final expectedNewNonceNHash = sha1(expectedNewNonceN);
    final result = setClientDHparamsAnswer;

    if (result is DhGenOk) {
      print(
          '0x${hexToStr(expectedNewNonceNHash.skip(4))} == ${result.newNonceHash1}');
    }

    final authKeyID =
        BinaryReader(Uint8List.fromList(authKeyHash.skip(12).toList()))
            .readInt64(false);

    final saltLeft = BinaryReader(Uint8List.fromList(pqInnerData.newNonce.data))
        .readInt64(false);

    final saltRight = BinaryReader(Uint8List.fromList(resPQ.serverNonce.data))
        .readInt64(false);

    final ak = AuthorizationKey(
      authKeyID,
      authKey,
      saltLeft ^ saltRight,
    );

    return ak;
  }

  Future<AuthorizationKey> exchange() async {
    final newNonce = Int256.random();
    final resPQ = await _reqPqMulti();
    await Future.delayed(const Duration(milliseconds: 200));
    final serverDHparams = await _reqDHParams(resPQ, newNonce);
    await Future.delayed(const Duration(milliseconds: 200));
    final ak = await _createAuthKey(
      resPQ,
      serverDHparams,
      newNonce,
    );

    return ak;
  }

  @override
  Object getKey(MtTask task) {
    final params = task.method;
    switch (params) {
      case ReqPqMultiMethod():
        return params.nonce.toString();
      case ReqDHParamsMethod():
        return '${params.nonce}-${params.serverNonce}';
      case SetClientDHParamsMethod():
        return '${params.nonce}-${params.serverNonce}';
      case _:
        l.Log.e(params.toJson().logPretty());
        return super.getKey(task);
    }
  }

  @override
  void send(MtTask task) {
    final buffer = encodeNoAuth(task.method, task.idSeq);

    obfuscation.send.encryptDecrypt(buffer, buffer.length);
    sender.add(Uint8List.fromList(buffer));
  }

  late final tgTask = TgTask(this);

  @override
  Future<Result<TlObject>> invoke(TlMethod method) =>
      tgTask.createTask(method).future;

  @override
  bool get preferEncryption => false;
}
