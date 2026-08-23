import 'dart:typed_data';

import 'package:ledger_bitcoin/src/operations/bitcoin_sign_psbt_operation.dart';
import 'package:ledger_bitcoin/src/utils/int_extension.dart';
import 'package:test/test.dart';

void main() {
  test('parses a SegWit partial signature response', () {
    final pubkey = Uint8List.fromList([0x02, ...List.filled(32, 0x11)]);
    final signature = Uint8List.fromList([0x30, 0x01, 0x01]);
    final payload = Uint8List.fromList([
      ...300.toVarint(),
      pubkey.length,
      ...pubkey,
      ...signature,
    ]);

    final result = parseSignPsbtPartialSignature(payload);

    expect(result.$1, 300);
    expect(result.$2, pubkey);
    expect(result.$3, signature);
  });

  test('rejects unsupported signing responses', () {
    final taggedPayload = Uint8List.fromList([
      ...0x10000.toVarint(),
      33,
      ...List.filled(34, 0x01),
    ]);

    expect(
      () => parseSignPsbtPartialSignature(taggedPayload),
      throwsFormatException,
    );
  });
}
