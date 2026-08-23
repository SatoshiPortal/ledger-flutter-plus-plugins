import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:ledger_bitcoin/src/bitcoin_transformer.dart';
import 'package:ledger_bitcoin/src/client_command_interpreter.dart';
import 'package:ledger_bitcoin/src/ledger_app_version.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_extended_public_key_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_master_fingerprint_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_register_wallet_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_sign_message_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_sign_psbt_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_version_operation.dart';
import 'package:ledger_bitcoin/src/operations/bitcoin_wallet_address_operation.dart';
import 'package:ledger_bitcoin/src/psbt/constants.dart';
import 'package:ledger_bitcoin/src/psbt/merkelized_psbt.dart';
import 'package:ledger_bitcoin/src/psbt/psbt_converter.dart';
import 'package:ledger_bitcoin/src/psbt/psbt_extractor.dart';
import 'package:ledger_bitcoin/src/psbt/psbt_finalizer.dart';
import 'package:ledger_bitcoin/src/psbt/psbtv2.dart';
import 'package:ledger_bitcoin/src/utils/bip32_path.dart';
import 'package:ledger_bitcoin/src/utils/create_key_helper.dart';
import 'package:ledger_bitcoin/src/utils/ledger_extension.dart';
import 'package:ledger_bitcoin/src/utils/merkle/merkle.dart';
import 'package:ledger_bitcoin/src/utils/uint8list_extension.dart';
import 'package:ledger_bitcoin/src/wallet_policy.dart';
import 'package:ledger_flutter_plus/ledger_flutter_plus.dart';

class BitcoinLedgerApp {
  BitcoinTransformer transformer;
  final LedgerConnection connection;

  final String derivationPath;
  final WalletPolicy walletPolicy;

  BitcoinLedgerApp(
    this.connection, {
    this.transformer = const BitcoinTransformer(),
    this.derivationPath = "m/84'/0'/0'/0/0",
    WalletPolicy? walletPolicy,
  }) : walletPolicy = walletPolicy ?? NativeSegwitWalletPolicy([]);

  factory BitcoinLedgerApp.nativeSegwit(LedgerConnection connection, {
    BitcoinTransformer transformer = const BitcoinTransformer(),
    String derivationPath = "m/84'/0'/0'/0/0",
  }) => BitcoinLedgerApp(connection, transformer: transformer, derivationPath: derivationPath, walletPolicy: NativeSegwitWalletPolicy([]));

  factory BitcoinLedgerApp.nestedSegwit(LedgerConnection connection, {
    BitcoinTransformer transformer = const BitcoinTransformer(),
    String derivationPath = "m/49'/0'/0'/0/0",
  }) => BitcoinLedgerApp(connection, transformer: transformer, derivationPath: derivationPath, walletPolicy: NestedSegwitWalletPolicy([]));

  factory BitcoinLedgerApp.legacy(LedgerConnection connection, {
    BitcoinTransformer transformer = const BitcoinTransformer(),
    String derivationPath = "m/44'/0'/0'/0/0",
  }) => BitcoinLedgerApp(connection, transformer: transformer, derivationPath: derivationPath, walletPolicy: LegacyWalletPolicy([]));

  factory BitcoinLedgerApp.taproot(LedgerConnection connection, {
    BitcoinTransformer transformer = const BitcoinTransformer(),
    String derivationPath = "m/86'/0'/0'/0/0",
  }) => BitcoinLedgerApp(connection, transformer: transformer, derivationPath: derivationPath, walletPolicy: TaprootWalletPolicy([]));

  Future<List<String>> getAccounts(
      {String? accountsDerivationPath, bool display = false}) async {
    final bipPath =
        BIPPath.fromString(accountsDerivationPath ?? derivationPath);
    final masterFingerprint = await getMasterFingerprint();
    final accountXPub = await getXPubKey(
        derivationPath: bipPath.toHardenedBIPPath().toString());

    final addr = await _getWalletAddress(
      path: bipPath,
      accountXPub: accountXPub,
      masterFingerprint: masterFingerprint,
      descrTempl: walletPolicy.descriptorTemplate,
      display: display,
    );
    return [addr.toAsciiString()];
  }

  Future<LedgerAppVersion> getVersion(LedgerDevice device) =>
      connection.sendOperation<LedgerAppVersion>(BitcoinVersionOperation(),
          transformer: transformer);

  /// Returns an extended public key at the given derivation path, serialized as per BIP-32
  Future<String> getXPubKey(
          {required String derivationPath, bool displayPublicKey = false}) =>
      connection.sendOperation<String>(
          BitcoinExtendedPublicKeyOperation(
              displayPublicKey: displayPublicKey,
              derivationPath: derivationPath),
          transformer: transformer);

  /// Returns the fingerprint of the master public key
  Future<Uint8List> getMasterFingerprint() =>
      connection.sendOperation<Uint8List>(BitcoinMasterFingerprintOperation(),
          transformer: transformer);

  /// Registers a protocol-v1 wallet policy and returns the HMAC that must be
  /// supplied with future address and signing requests for that policy.
  Future<({Uint8List walletId, Uint8List walletHMAC})> registerWallet({
    required WalletPolicy walletPolicy,
  }) async {
    _ensureRegisteredWalletPolicy(walletPolicy);
    final clientInterpreter = ClientCommandInterpreter(() {})
      ..addKnownWalletPolicy(walletPolicy);
    final response = await connection.runFlow(
      BitcoinRegisterWalletOperation(walletPolicy: walletPolicy),
      clientInterpreter,
    );
    if (response.length != 64) {
      throw Exception('Invalid wallet registration response');
    }

    final walletId = response.sublist(0, 32);
    if (!listEquals(walletId, walletPolicy.id)) {
      throw Exception('Unexpected wallet policy id');
    }
    return (walletId: walletId, walletHMAC: response.sublist(32));
  }

  /// Gets an address from a registered wallet policy, displaying it on the
  /// Ledger by default.
  Future<Uint8List> getWalletAddressWithPolicy({
    required WalletPolicy walletPolicy,
    required Uint8List walletHMAC,
    required int change,
    required int addressIndex,
    bool display = true,
  }) async {
    _ensureRegisteredWalletPolicy(walletPolicy);
    _validateWalletHMAC(walletHMAC);
    if (change != 0 && change != 1) {
      throw ArgumentError.value(change, 'change', 'Must be 0 or 1');
    }
    if (addressIndex < 0 || addressIndex >= 1 << 31) {
      throw ArgumentError.value(
        addressIndex,
        'addressIndex',
        'Must be between 0 and 2^31 - 1',
      );
    }

    final clientInterpreter = ClientCommandInterpreter(() {})
      ..addKnownWalletPolicy(walletPolicy);
    return connection.runFlow(
      BitcoinWalletAddressOperation(
        walletPolicy: walletPolicy,
        walletHMAC: walletHMAC,
        change: change,
        addressIndex: addressIndex,
        displayWalletAddress: display,
        protocolVersion: 1,
      ),
      clientInterpreter,
    );
  }

  /// Adds non-Taproot signatures returned by the Ledger and returns an updated
  /// PSBT in version 0 format without finalizing the transaction.
  Future<Uint8List> signPsbtWithWalletPolicy({
    required Uint8List psbt,
    required WalletPolicy walletPolicy,
    required Uint8List walletHMAC,
  }) async {
    _ensureRegisteredWalletPolicy(walletPolicy);
    _validateWalletHMAC(walletHMAC);
    final parsedPsbt = PsbtV2()..deserialize(psbt);
    final yielded = await _requestPsbtSignatures(
      psbt: parsedPsbt,
      walletPolicy: walletPolicy,
      walletHMAC: walletHMAC,
      protocolVersion: 1,
    );

    for (final payload in yielded) {
      final (inputIndex, pubkey, signature) =
          parseSignPsbtPartialSignature(payload);
      if (inputIndex >= parsedPsbt.getGlobalInputCount() ||
          parsedPsbt.getInputBip32Derivation(inputIndex, pubkey) == null) {
        throw Exception('Unexpected signature returned by Ledger');
      }

      final existingSignature =
          parsedPsbt.getInputPartialSig(inputIndex, pubkey);
      if (existingSignature != null &&
          !listEquals(existingSignature, signature)) {
        throw Exception('Ledger returned a conflicting signature');
      }
      parsedPsbt.setInputPartialSig(inputIndex, pubkey, signature);
    }
    return parsedPsbt.asPsbtV0();
  }

  Future<Uint8List> signTransaction(Uint8List transaction) {
    final psbt = PsbtV2();
    psbt.deserialize(transaction);
    return signPsbt(psbt: psbt);
  }

  // Base 64 Encoded v, r, s
  Future<Uint8List> signMessage(
      {required Uint8List message, String? signDerivationPath}) async {
    final clientInterpreter = ClientCommandInterpreter(() => {});

    // prepare ClientCommandInterpreter
    final nChunks = (message.length / 64).ceil();
    final chunks = <Uint8List>[];
    for (var i = 0; i < nChunks; i++) {
      final end = min(message.length, 64 * i + 64);
      chunks.add(message.sublist(64 * i, end));
    }

    clientInterpreter.addKnownList(chunks);
    final chunksRoot = Merkle(chunks.map((m) => hashLeaf(m)).toList()).root;

    return await connection.runFlow(
      BitcoinSignMessageOperation(
        derivationPath: signDerivationPath ?? derivationPath,
        messageLength: message.length,
        messageMerkleRoot: chunksRoot,
      ),
      clientInterpreter,
    );
  }

  /// Creates a wallet policy instance of the same type as the configured wallet policy
  WalletPolicy _createWalletPolicyInstance(List<String> keys) {
    if (walletPolicy is LegacyWalletPolicy) {
      return LegacyWalletPolicy(keys);
    } else if (walletPolicy is NativeSegwitWalletPolicy) {
      return NativeSegwitWalletPolicy(keys);
    } else if (walletPolicy is NestedSegwitWalletPolicy) {
      return NestedSegwitWalletPolicy(keys);
    } else if (walletPolicy is TaprootWalletPolicy) {
      return TaprootWalletPolicy(keys);
    } else {
      return WalletPolicy("", walletPolicy.descriptorTemplate, keys);
    }
  }

  Future<Uint8List> _getWalletAddress({
    required BIPPath path,
    required String accountXPub,
    required Uint8List masterFingerprint,
    required String descrTempl,
    required bool display,
  }) async {
    final pathElements = path.toPathArray();
    final accountPath = path.hardenedPath;

    if (accountPath.length + 2 != pathElements.length) return Uint8List(0);

    final template = descrTempl.isNotEmpty ? descrTempl : walletPolicy.descriptorTemplate;
    final policy = WalletPolicy("", template,
        [createKey(masterFingerprint, accountPath, accountXPub)]);
    final changeAndIndex = pathElements.sublist(pathElements.length - 2);

    return _getWalletAddressWithPolicy(
        policy: policy,
        change: changeAndIndex.first,
        addressIndex: changeAndIndex.last,
        display: display);
  }

  Future<Uint8List> _getWalletAddressWithPolicy({
    required WalletPolicy policy,
    required int change,
    required int addressIndex,
    required bool display,
  }) async {
    final clientInterpreter = ClientCommandInterpreter(() {});
    clientInterpreter
        .addKnownList(policy.keys.map((k) => ascii.encode(k)).toList());
    clientInterpreter.addKnownPreimage(policy.serializeLegacy());

    return await connection.runFlow(
      BitcoinWalletAddressOperation(
        walletPolicy: policy,
        change: change,
        addressIndex: addressIndex,
        displayWalletAddress: display,
      ),
      clientInterpreter,
    );
  }

  Future<Uint8List> signPsbt({
    required PsbtV2 psbt,
  }) async {
    final bipPath = BIPPath.fromString(derivationPath);
    final masterFingerprint = await getMasterFingerprint();
    final accountXPub = await getXPubKey(
        derivationPath: bipPath.toHardenedBIPPath().toString());

    final policyKeys = [createKey(masterFingerprint, bipPath.hardenedPath, accountXPub)];
    final policy = _createWalletPolicyInstance(policyKeys);

    return _signPsbt(
        psbt: psbt,
        walletPolicy: policy);
  }

  Future<Uint8List> _signPsbt({
    required PsbtV2 psbt,
    required WalletPolicy walletPolicy,
    Uint8List? walletHMAC,
  }) async {
    final yielded = await _requestPsbtSignatures(
      psbt: psbt,
      walletPolicy: walletPolicy,
      walletHMAC: walletHMAC,
      protocolVersion: 0,
    );

    final sigs = <int, Uint8List>{};
    for (final inputAndSig in yielded) {
      sigs[inputAndSig[0]] = inputAndSig.sublist(1);
    }

    sigs.forEach((k, v) {
      // Note: Looking at BIP32 derivation does not work in the generic case,
      // since some inputs might not have a BIP32-derived pubkey.
      final pubkeys = psbt.getInputKeyDatas(k, PSBTIn.bip32Derivation);
      if (pubkeys.length != 1) {
        // No legacy BIP32_DERIVATION, assume we're using taproot.
        final pubkey = psbt.getInputKeyDatas(k, PSBTIn.tapBip32Derivation);
        if (pubkey.isEmpty) {
          throw Exception('Missing pubkey derivation for input $k');
        }
        psbt.setInputTapKeySig(k, v);
      } else {
        final pubkey = pubkeys[0];
        psbt.setInputPartialSig(k, pubkey, v);
      }
    });

    psbt.finalize();
    return psbt.extract();
  }

  Future<List<Uint8List>> _requestPsbtSignatures({
    required PsbtV2 psbt,
    required WalletPolicy walletPolicy,
    required int protocolVersion,
    Uint8List? walletHMAC,
  }) async {
    if (walletHMAC != null) {
      _validateWalletHMAC(walletHMAC);
    }

    final merkelizedPsbt = MerkelizedPsbt(psbt);
    final clientInterpreter = ClientCommandInterpreter(() {});
    if (protocolVersion == 0) {
      clientInterpreter
        ..addKnownList(walletPolicy.keys.map((key) => ascii.encode(key)))
        ..addKnownPreimage(walletPolicy.serializeLegacy());
    } else {
      clientInterpreter.addKnownWalletPolicy(walletPolicy);
    }
    clientInterpreter.addKnownMapping(merkelizedPsbt.globalMerkleMap);

    for (final map in merkelizedPsbt.inputMerkleMaps) {
      clientInterpreter.addKnownMapping(map);
    }
    for (final map in merkelizedPsbt.outputMerkleMaps) {
      clientInterpreter.addKnownMapping(map);
    }

    clientInterpreter.addKnownList(merkelizedPsbt.inputMapCommitments);
    final inputMapsRoot = Merkle(
      merkelizedPsbt.inputMapCommitments.map(hashLeaf),
    ).root;
    clientInterpreter.addKnownList(merkelizedPsbt.outputMapCommitments);
    final outputMapsRoot = Merkle(
      merkelizedPsbt.outputMapCommitments.map(hashLeaf),
    ).root;

    await connection.runFlow(
      BitcoinSignPsbtOperation(
        walletPolicy: walletPolicy,
        walletHMAC: walletHMAC,
        globalKeysValuesRoot: merkelizedPsbt.globalKeysValuesRoot,
        inputCount: merkelizedPsbt.getGlobalInputCount(),
        inputsMapsRoot: inputMapsRoot,
        outputCount: merkelizedPsbt.getGlobalOutputCount(),
        outputsMapsRoot: outputMapsRoot,
        protocolVersion: protocolVersion,
      ),
      clientInterpreter,
    );
    return clientInterpreter.yielded;
  }

  void _validateWalletHMAC(Uint8List walletHMAC) {
    if (walletHMAC.length != 32) {
      throw ArgumentError.value(
        walletHMAC.length,
        'walletHMAC.length',
        'Must be 32 bytes',
      );
    }
  }

  void _ensureRegisteredWalletPolicy(WalletPolicy policy) {
    if (policy is LegacyWalletPolicy ||
        policy is NativeSegwitWalletPolicy ||
        policy is NestedSegwitWalletPolicy ||
        policy is TaprootWalletPolicy) {
      throw ArgumentError(
        'Legacy default wallet policies cannot be used with registered wallet APIs',
      );
    }
    if (policy.name.isEmpty) {
      throw ArgumentError.value(
        policy.name,
        'walletPolicy.name',
        'Registered wallets require a name',
      );
    }
  }
}
