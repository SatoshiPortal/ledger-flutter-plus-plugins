import 'dart:typed_data';

import 'package:ledger_bitcoin/src/client_command_interpreter.dart';
import 'package:ledger_bitcoin/src/ledger/ledger_input_operation.dart';
import 'package:ledger_bitcoin/src/operations/framework/continue_interrupted_operation.dart';
import 'package:ledger_bitcoin/src/utils/uint8list_extension.dart';
import 'package:ledger_flutter_plus/ledger_flutter_plus.dart';

extension RunLedgerFlow on LedgerConnection {
  Future<Uint8List> runFlow(
    LedgerInputOperation<Uint8List> operation,
    ClientCommandInterpreter cci,
  ) async {
    var response = await sendOperation<Uint8List>(operation);

    while (_statusWord(response) == "e000") {
      final hwRequest = response.sublist(
        0,
        response.length - 2,
      ); // -2 because we need to remove the status bytes
      final commandResponse = cci.execute(hwRequest);

      response = await _continueOperation(
        device,
        data: commandResponse,
        protocolVersion: operation.p2,
      );
    }

    final status = _statusWord(response);
    if (status != "9000") {
      final message = switch (status) {
        "6a80" => "SW_INCORRECT_DATA",
        "6a82" => "SW_NOT_SUPPORTED",
        "6985" => "SW_DENIED_BY_USER",
        _ => "Ledger command failed with status $status",
      };
      throw Exception(message);
    }

    return response.sublist(
      0,
      response.length - 2,
    ); // -2 because we need to remove the status bytes
  }

  Future<Uint8List> _continueOperation(
    LedgerDevice device, {
    required Uint8List data,
    required int protocolVersion,
  }) => sendOperation<Uint8List>(
    ContinueInterruptedOperation(data, protocolVersion: protocolVersion),
  );
}

String _statusWord(Uint8List response) {
  if (response.length < 2) {
    throw const FormatException('Ledger response is missing its status word');
  }
  return response.sublist(response.length - 2).toHexString();
}
