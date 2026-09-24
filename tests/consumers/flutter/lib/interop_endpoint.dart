import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:rockets_im_stage0/rockets_im_stage0.dart' as sdk;

/// 仅本机验收的串行控制端，不在控制器内替代SDK处理密码操作。
class InteropEndpoint {
  InteropEndpoint(String url, this.runId, this.endpointId) {
    final uri = Uri.parse(url);
    if (uri.scheme != 'http' ||
        !{'127.0.0.1', '10.0.2.2'}.contains(uri.host) ||
        !uri.hasPort ||
        uri.port < 1 ||
        uri.port > 65535 ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment ||
        !{'', '/'}.contains(uri.path) ||
        !_validId(runId) ||
        endpointId !=
            (Platform.isAndroid ? 'flutter-android' : 'flutter-ios')) {
      throw StateError('invalid local interop configuration');
    }
    _base = uri.replace(path: '/interop/$runId/$endpointId');
    _http.connectionTimeout = const Duration(seconds: 5);
  }

  final String runId;
  final String endpointId;
  late final Uri _base;
  final HttpClient _http = HttpClient();
  final Map<String, sdk.Stage0Device> _handles = {};
  final Set<String> _seen = {};
  bool _active = true;
  static const _limit = 1024 * 1024;

  void cancel() {
    _active = false;
    _http.close(force: true);
  }

  Future<String> run() async {
    try {
      await sdk.initialize();
      await _post('ready', {
        'run_id': runId,
        'endpoint_id': endpointId,
        'sdk_version': sdk.packageVersion,
        'platform': endpointId,
      });
      while (_active) {
        final command = await _request('GET', 'next');
        if (command == null) continue;
        if (command['run_id'] != runId)
          throw StateError('command run mismatch');
        final commandId = _string(command, 'command_id');
        if (!_validId(commandId) ||
            _seen.length >= 10000 ||
            !_seen.add(commandId)) {
          throw StateError('duplicate or excessive command');
        }
        final result = <String, Object?>{
          'run_id': runId,
          'endpoint_id': endpointId,
          'command_id': commandId,
        };
        try {
          result['value'] = await _execute(command);
          result['ok'] = true;
        } catch (error) {
          // 固定绑定将Result的String错误直接抛出；其他类型不推测密码状态。
          final match = error is String
              ? RegExp(
                  r'^([a-z_]+); device_poisoned=(true|false)$',
                ).firstMatch(error)
              : null;
          result['ok'] = false;
          result['error'] = match == null
              ? {
                  'origin': 'harness',
                  'code': 'unclassified_error',
                  'device_poisoned': false,
                  'message': error.runtimeType.toString(),
                }
              : {
                  'origin': 'sdk',
                  'code': match.group(1),
                  'device_poisoned': match.group(2) == 'true',
                  'message': error.toString().substring(
                    0,
                    error.toString().length.clamp(0, 512),
                  ),
                };
        }
        await _post('result', result);
        if (command['op'] == 'shutdown') return 'finished';
      }
      return 'cancelled';
    } finally {
      _http.close(force: true);
      for (final device in _handles.values) {
        await device.close();
      }
      _handles.clear();
    }
  }

  Future<Object?> _execute(Map<String, Object?> command) async {
    final op = _string(command, 'op');
    final arguments = command['args'];
    if (arguments is! Map<String, Object?> ||
        arguments.values.any((value) => value is! String)) {
      throw StateError('args must contain strings');
    }
    if (op == 'shutdown') {
      for (final device in _handles.values) {
        await device.close();
      }
      _handles.clear();
      return null;
    }
    final handle = _string(command, 'handle');
    if (!_validId(handle)) throw StateError('invalid handle');
    if (op == 'new') {
      if (_handles.containsKey(handle) || _handles.length >= 32)
        throw StateError('handle exists or limit exceeded');
      _handles[handle] = await sdk.newDevice(
        serviceId: _string(arguments, 'service_id'),
        accountId: _string(arguments, 'account_id'),
        deviceId: _string(arguments, 'device_id'),
      );
      return null;
    }
    final device = _handles[handle];
    if (device == null) throw StateError('unknown handle');
    switch (op) {
      case 'identity':
        return base64Encode(await device.identityKey());
      case 'key_package':
        return base64Encode(await device.keyPackage());
      case 'create_group':
        return base64Encode(
          await device.createGroup(
            conversationId: _string(arguments, 'conversation_id'),
            peerAccountId: _string(arguments, 'peer_account_id'),
            peerDeviceId: _string(arguments, 'peer_device_id'),
            peerIdentityKey: _bytes(arguments, 'peer_identity_key'),
            keyPackage: _bytes(arguments, 'key_package'),
          ),
        );
      case 'join_group':
        await device.joinGroup(
          conversationId: _string(arguments, 'conversation_id'),
          creatorAccountId: _string(arguments, 'creator_account_id'),
          creatorDeviceId: _string(arguments, 'creator_device_id'),
          creatorIdentityKey: _bytes(arguments, 'creator_identity_key'),
          welcome: _bytes(arguments, 'welcome'),
        );
        return null;
      case 'encrypt':
        return base64Encode(
          await device.encrypt(plaintext: _bytes(arguments, 'plaintext')),
        );
      case 'decrypt':
        return base64Encode(
          await device.decrypt(ciphertext: _bytes(arguments, 'ciphertext')),
        );
      case 'close':
        await device.close();
        return null;
      case 'drop':
        await device.close();
        _handles.remove(handle);
        return null;
      default:
        throw StateError('unknown operation');
    }
  }

  Future<void> _post(String path, Map<String, Object?> body) async {
    final response = await _request('POST', path, body);
    if (response?['ok'] != true)
      throw StateError('controller did not acknowledge result');
  }

  Future<Map<String, Object?>?> _request(
    String method,
    String path, [
    Map<String, Object?>? body,
  ]) async {
    if (!_active) throw StateError('endpoint cancelled');
    final request = await _http.openUrl(
      method,
      _base.replace(path: '${_base.path}/$path'),
    );
    request.followRedirects = false;
    if (body != null) {
      final bytes = utf8.encode(jsonEncode(body));
      if (bytes.length > _limit) throw StateError('HTTP request exceeds limit');
      request.headers.contentType = ContentType.json;
      request.contentLength = bytes.length;
      request.add(bytes);
    }
    final response = await request.close().timeout(const Duration(seconds: 20));
    if (method == 'GET' && response.statusCode == 204) {
      await response.drain<void>();
      return null;
    }
    if (response.statusCode != 200)
      throw HttpException(
        'HTTP control channel failed: ${response.statusCode}',
      );
    final buffer = BytesBuilder(copy: false);
    await for (final chunk in response.timeout(const Duration(seconds: 20))) {
      if (buffer.length + chunk.length > _limit)
        throw StateError('HTTP response exceeds limit');
      buffer.add(chunk);
    }
    final decoded = jsonDecode(utf8.decode(buffer.takeBytes()));
    if (decoded is! Map<String, Object?>)
      throw StateError('HTTP response is not an object');
    return decoded;
  }

  static String _string(Map<String, Object?> object, String key) {
    final value = object[key];
    if (value is! String) throw StateError('expected string $key');
    return value;
  }

  static Uint8List _bytes(Map<String, Object?> object, String key) {
    final encoded = _string(object, key);
    final bytes = base64Decode(encoded);
    if (base64Encode(bytes) != encoded)
      throw StateError('non-canonical Base64');
    return bytes;
  }

  static bool _validId(String value) =>
      RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(value);
}
