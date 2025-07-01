import 'dart:typed_data';

import 'package:tg_api/tg_api.dart';

import '../tg.dart';
import 'crypto.dart';
import 'extensions.dart';
import 'private.dart';
import 'public_keys.dart';

Uint8List encodeNoAuth(
  TlObject message,
  IdSeq m,
) {
  final messageBuffer = message.asUint8List();
  final buffer = <int>[
    ...(messageBuffer.length + 20).asUint32List(),
    ...0.asUint64List(),
    ...m.id.asUint64List(),
    ...messageBuffer.length.asUint32List(),
    ...messageBuffer,
  ];

  return Uint8List.fromList(buffer);
}

Uint8List encodeWithAuth(
  TlObject message,
  IdSeq m,
  int sessionId,
  AuthorizationKey auth,
) {
  final messageBuffer = message.asUint8List();
  final clearLength = messageBuffer.length + 32;
  final padding = ((0x7FFFFFF0 - clearLength) % 16);
  final paddingRandomized = padding + ((2 + rng.nextInt(14)) * 16);
  final paddingData = Uint8List(paddingRandomized);
  rng.getBytes(paddingData);

  final clear = <int>[
    ...auth.key.skip(88).take(32),
    ...auth.salt.asUint64List(),
    ...sessionId.asUint64List(),
    ...m.id.asUint64List(),
    ...m.seqno.asUint32List(),
    ...messageBuffer.length.asUint32List(),
    ...messageBuffer,
    ...paddingData,
  ];

  final msgKey = Uint8List.fromList(sha256(clear));
  final encryptedData = encryptDecryptMessage(
    Uint8List.fromList(clear.skip(32).toList()),
    true,
    0,
    auth.key,
    msgKey,
    8,
  );

  final writerLength = 8 + 16 + encryptedData.length;

  final buffer = [
    ...writerLength.asUint32List(),
    ...auth.id.asUint64List(),
    ...msgKey.skip(8).take(16),
    ...encryptedData,
  ];

  return Uint8List.fromList(buffer);
}

class MessageIdSequenceGenerator {
  int _lastSentMessageId = 0;
  int _seqno = 0;
  int serverTicksOffset = 0;

  void updateSeqno(int newSeqno) {
    _seqno = newSeqno;
  }

  IdSeq next(bool preferEncryption) {
    var msgId = DateTime.now().ticks + serverTicksOffset - 621355968000000000;
    msgId = msgId * 428 +
        (msgId >> 24) *
            25110956; // approximately unixtime*2^32 and divisible by 4

    if (msgId <= _lastSentMessageId) {
      msgId = _lastSentMessageId += 4;
    } else {
      _lastSentMessageId = msgId;
    }

    final seqno = preferEncryption ? _seqno++ * 2 + 1 : _seqno * 2;

    return IdSeq(msgId, seqno);
  }
}

class IdSeq {
  const IdSeq(this.id, this.seqno);
  final int id;
  final int seqno;
}
