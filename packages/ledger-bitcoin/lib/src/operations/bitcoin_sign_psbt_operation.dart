import 'dart:typed_data';

import 'package:ledger_bitcoin/src/ledger/ledger_input_operation.dart';
import 'package:ledger_bitcoin/src/utils/buffer_reader.dart';
import 'package:ledger_bitcoin/src/utils/int_extension.dart';
import 'package:ledger_bitcoin/src/wallet_policy.dart';
import 'package:ledger_flutter_plus/ledger_flutter_plus_dart.dart';

class BitcoinSignPsbtOperation extends LedgerInputOperation<Uint8List> {
  final WalletPolicy walletPolicy;
  final Uint8List? walletHMAC;

  final int inputCount;
  final int outputCount;

  final Uint8List globalKeysValuesRoot;
  final Uint8List inputsMapsRoot;
  final Uint8List outputsMapsRoot;
  final int protocolVersion;

  BitcoinSignPsbtOperation({
    required this.walletPolicy,
    required this.globalKeysValuesRoot,
    required this.inputCount,
    required this.inputsMapsRoot,
    required this.outputCount,
    required this.outputsMapsRoot,
    this.walletHMAC,
    this.protocolVersion = 0,
  })  : assert(protocolVersion == 0 || protocolVersion == 1),
        super(0xE1, 0x04);

  @override
  Future<Uint8List> read(ByteDataReader reader) async =>
      reader.read(reader.remainingLength);

  @override
  int get p1 => 0x00;

  @override
  int get p2 => protocolVersion;

  @override
  Future<Uint8List> writeInputData() async {
    final walletHMACBytes = walletHMAC ?? Uint8List(32);

    final writer = ByteDataWriter()
      ..write(globalKeysValuesRoot)
      ..write(inputCount.toVarint())
      ..write(inputsMapsRoot)
      ..write(outputCount.toVarint())
      ..write(outputsMapsRoot)
      ..write(protocolVersion == 0 ? walletPolicy.legacyId : walletPolicy.id)
      ..write(walletHMACBytes);

    return writer.toBytes();
  }
}

(int, Uint8List, Uint8List) parseSignPsbtPartialSignature(Uint8List payload) {
  final reader = BufferReader(payload);
  final inputIndex = reader.readVarInt();
  if (inputIndex > 0xffff || reader.available() < 2) {
    throw FormatException('Unsupported SIGN_PSBT response');
  }

  final pubkeyLength = reader.readUInt8();
  if (pubkeyLength != 33 || reader.available() <= pubkeyLength) {
    throw FormatException('Unsupported SIGN_PSBT public key');
  }

  final pubkey = reader.readSlice(pubkeyLength);
  final signature = reader.readSlice(reader.available());
  return (inputIndex, pubkey, signature);
}
