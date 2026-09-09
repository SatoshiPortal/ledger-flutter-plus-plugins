import 'dart:convert';
import 'dart:typed_data';

import 'package:ledger_bitcoin/src/utils/buffer_writer.dart';
import 'package:ledger_bitcoin/src/utils/merkle/merkle.dart';
import 'package:ledger_bitcoin/src/utils/utils.dart';

class WalletPolicy {
  static const _version = 2;

  final String name;
  final String descriptorTemplate;
  final List<String> keys;

  /// Creates and instance of a wallet policy.
  /// [name] an ASCII string, up to 64 bytes long; it must be an empty
  /// string for default wallet policies.
  /// [descriptorTemplate] the wallet policy template
  /// [keys] and array of the keys, with the key derivation information
  WalletPolicy(this.name, this.descriptorTemplate, this.keys);

  /// Returns the unique 32-bytes id of this wallet policy.
  Uint8List get id => sha256Hasher(serialize());

  /// Serializes the wallet policy for transmission via the hardware wallet protocol.
  Uint8List serialize() {
    final nameBytes = ascii.encode(name);
    if (nameBytes.length > 64 ||
        nameBytes.any((byte) => byte < 0x20 || byte > 0x7e) ||
        (name.isNotEmpty && name.trim() != name)) {
      throw ArgumentError.value(name, 'name', 'Invalid wallet name');
    }

    final descriptorBytes = ascii.encode(descriptorTemplate);
    final keyBuffers = keys.map((key) => ascii.encode(key)).toList();
    final merkle = Merkle(keyBuffers.map((k) => hashLeaf(k)).toList());

    final buf = BufferWriter()
      ..writeUInt8(_version)
      ..writeVarSlice(nameBytes)
      ..writeVarInt(descriptorBytes.length)
      ..writeSlice(sha256Hasher(descriptorBytes))
      ..writeVarInt(keys.length)
      ..writeSlice(merkle.root);
    return buf.buffer();
  }

  Uint8List get legacyId => sha256Hasher(serializeLegacy());

  Uint8List serializeLegacy() {
    final keyBuffers = keys.map((key) => ascii.encode(key));
    final merkle = Merkle(keyBuffers.map((key) => hashLeaf(key)).toList());

    final buf = BufferWriter()
      ..writeUInt8(0x01)
      ..writeUInt8(0)
      ..writeVarSlice(ascii.encode(descriptorTemplate))
      ..writeVarInt(keys.length)
      ..writeSlice(merkle.root);
    return buf.buffer();
  }
}

/// Legacy addresses as per BIP-44
class LegacyWalletPolicy extends WalletPolicy {
  LegacyWalletPolicy(List<String> keys) : super("", "pkh(@0)", keys);
}

/// Native segwit addresses per BIP-84
class NativeSegwitWalletPolicy extends WalletPolicy {
  NativeSegwitWalletPolicy(List<String> keys) : super("", "wpkh(@0)", keys);
}

/// Nested segwit addresses as per BIP-49
class NestedSegwitWalletPolicy extends WalletPolicy {
  NestedSegwitWalletPolicy(List<String> keys) : super("", "sh(wpkh(@0))", keys);
}

/// Single Key P2TR as per BIP-86
class TaprootWalletPolicy extends WalletPolicy {
  TaprootWalletPolicy(List<String> keys) : super("", "tr(@0)", keys);
}
