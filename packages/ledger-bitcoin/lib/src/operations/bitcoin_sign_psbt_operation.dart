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
  if (pubkeyLength != 32 && pubkeyLength != 33 && pubkeyLength != 64) {
    throw FormatException('Unsupported SIGN_PSBT public key');
  }
  if (reader.available() <= pubkeyLength) {
    throw FormatException('Unsupported SIGN_PSBT response');
  }

  final pubkey = reader.readSlice(pubkeyLength);
  final signature = reader.readSlice(reader.available());
  if (pubkeyLength == 33) {
    if (!_isValidEcdsaSignature(signature)) {
      throw FormatException('Invalid ECDSA signature');
    }
  } else if (!_isValidTaprootSignature(signature)) {
    throw FormatException('Invalid Taproot signature');
  }
  return (inputIndex, pubkey, signature);
}

bool _isValidEcdsaSignature(Uint8List signature) {
  if (signature.length < 9 || signature.length > 73) return false;
  if (signature[0] != 0x30 || signature[1] != signature.length - 3) {
    return false;
  }

  final rLength = signature[3];
  if (5 + rLength >= signature.length) return false;
  final sLength = signature[5 + rLength];
  if (rLength + sLength + 7 != signature.length ||
      signature[2] != 0x02 ||
      rLength == 0 ||
      signature[4] & 0x80 != 0 ||
      rLength > 1 && signature[4] == 0 && signature[5] & 0x80 == 0 ||
      signature[4 + rLength] != 0x02 ||
      sLength == 0 ||
      signature[6 + rLength] & 0x80 != 0 ||
      sLength > 1 &&
          signature[6 + rLength] == 0 &&
          signature[7 + rLength] & 0x80 == 0) {
    return false;
  }
  return _isDefinedSighash(signature.last);
}

bool _isValidTaprootSignature(Uint8List signature) =>
    signature.length == 64 ||
    signature.length == 65 && _isDefinedSighash(signature.last);

bool _isDefinedSighash(int sighash) =>
    sighash == 0x01 ||
    sighash == 0x02 ||
    sighash == 0x03 ||
    sighash == 0x81 ||
    sighash == 0x82 ||
    sighash == 0x83;

void validateSignPsbtSignatureSighash({
  required Uint8List signature,
  required int? requestedSighash,
  required bool isTaproot,
}) {
  if (requestedSighash == null) return;
  final returnedSighash =
      isTaproot && signature.length == 64 ? 0x00 : signature.last;
  if (returnedSighash != requestedSighash) {
    throw const FormatException(
      'Ledger returned a signature with an unexpected sighash type',
    );
  }
}
