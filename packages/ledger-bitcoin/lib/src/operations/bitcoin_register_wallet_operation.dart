import 'dart:typed_data';

import 'package:ledger_bitcoin/src/ledger/ledger_input_operation.dart';
import 'package:ledger_bitcoin/src/utils/int_extension.dart';
import 'package:ledger_bitcoin/src/wallet_policy.dart';
import 'package:ledger_flutter_plus/ledger_flutter_plus_dart.dart';

class BitcoinRegisterWalletOperation extends LedgerInputOperation<Uint8List> {
  final WalletPolicy walletPolicy;

  BitcoinRegisterWalletOperation({required this.walletPolicy})
      : super(0xE1, 0x02);

  @override
  int get p1 => 0x00;

  @override
  int get p2 => 0x01;

  @override
  Future<Uint8List> read(ByteDataReader reader) async =>
      reader.read(reader.remainingLength);

  @override
  Future<Uint8List> writeInputData() async {
    final serializedPolicy = walletPolicy.serialize();
    return Uint8List.fromList([
      ...serializedPolicy.length.toVarint(),
      ...serializedPolicy,
    ]);
  }
}
