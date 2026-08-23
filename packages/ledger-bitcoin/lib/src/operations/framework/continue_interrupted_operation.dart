import 'dart:typed_data';

import 'package:ledger_bitcoin/src/ledger/ledger_input_operation.dart';
import 'package:ledger_flutter_plus/ledger_flutter_plus_dart.dart';

class ContinueInterruptedOperation extends LedgerInputOperation<Uint8List> {
  final Uint8List inputData;
  final int protocolVersion;

  ContinueInterruptedOperation(this.inputData, {this.protocolVersion = 0})
      : assert(protocolVersion == 0 || protocolVersion == 1),
        super(0xF8, 0x01);

  @override
  Future<Uint8List> read(ByteDataReader reader) async =>
      reader.read(reader.remainingLength);

  @override
  int get p1 => 0x00;

  @override
  int get p2 => protocolVersion;

  @override
  Future<Uint8List> writeInputData() async => inputData;
}
