import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:rocket_im_stage0/rocket_im_stage0.dart' as sdk;
import 'interop_endpoint.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const ConsumerApp());
}

class ConsumerApp extends StatefulWidget {
  const ConsumerApp({super.key});
  @override
  State<ConsumerApp> createState() => _ConsumerAppState();
}

class _ConsumerAppState extends State<ConsumerApp> {
  String _status = '正在验证本地 Release 包…';
  InteropEndpoint? _interop;

  @override
  void initState() {
    super.initState();
    const url = String.fromEnvironment('ROCKET_INTEROP_URL');
    if (url.isNotEmpty) {
      _runInterop(url);
    } else {
      _verify();
    }
  }

  Future<void> _runInterop(String url) async {
    try {
      final endpoint = InteropEndpoint(
        url,
        const String.fromEnvironment('ROCKET_INTEROP_RUN_ID'),
        const String.fromEnvironment('ROCKET_INTEROP_ENDPOINT_ID'),
      );
      _interop = endpoint;
      final status = await endpoint.run();
      if (mounted) setState(() => _status = '互通控制：$status');
    } catch (error) {
      debugPrint('ROCKET_INTEROP_HARNESS_FAILED:${error.runtimeType}');
      if (mounted) setState(() => _status = '互通装置失败：${error.runtimeType}');
    }
  }

  @override
  void dispose() {
    _interop?.cancel();
    super.dispose();
  }

  Future<void> _verify() async {
    final result = <String, Object>{
      'run_id': const String.fromEnvironment('RUN_ID', defaultValue: 'manual'),
      'platform': 'flutter',
      'package_version': sdk.packageVersion,
    };
    try {
      const rejectedVersion = bool.fromEnvironment('NEGATIVE_VERSION');
      if (rejectedVersion) {
        await _verifyRejectedVersion();
      } else {
        await _verifyPublicApi();
      }
      result.addAll({
        'status': 'passed',
        'scenario': rejectedVersion ? 'version-rejected' : 'public-api',
        'checks': rejectedVersion ? 2 : 8,
      });
    } catch (error) {
      result.addAll({'status': 'failed', 'error': error.toString()});
    }
    final encoded = jsonEncode(result);
    // 实验输出只含结果，不打印身份钥、KeyPackage、密文或内部状态。
    debugPrint('ROCKET_STAGE0_RESULT:$encoded');
    if (mounted) setState(() => _status = encoded);
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
    home: Scaffold(
      appBar: AppBar(title: const Text('Rocket Stage 0')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: SelectableText(_status),
      ),
    ),
  );
}

Future<void> _verifyRejectedVersion() async {
  var initializationRejected = false;
  try {
    await sdk.initialize(expectedVersion: 'deliberately-incompatible');
  } on StateError catch (error) {
    initializationRejected = error.message.toString().contains('版本不匹配');
  }
  _require(initializationRejected, '不兼容版本未拒绝初始化');
  var deviceRejected = false;
  try {
    await sdk.newDevice(
      serviceId: 'release-local',
      accountId: 'alice',
      deviceId: 'version-negative',
    );
  } on StateError catch (error) {
    deviceRejected = error.message.toString().contains('版本不匹配');
  }
  _require(deviceRejected, '初始化失败后仍可绕过创建设备');
}

bool _same(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

void _require(bool condition, String reason) {
  if (!condition) throw StateError(reason);
}

Future<void> _verifyPublicApi() async {
  await sdk.initialize();
  final alice = await sdk.newDevice(
    serviceId: 'release-local',
    accountId: 'alice',
    deviceId: 'alice-flutter',
  );
  final bob = await sdk.newDevice(
    serviceId: 'release-local',
    accountId: 'bob',
    deviceId: 'bob-flutter',
  );
  try {
    var malformedRejected = false;
    try {
      // dynamic仅用于验证公开类型边界，非法整数不得在FFI内静默截断。
      final dynamic device = alice;
      await device.encrypt(plaintext: <int>[-1, 256]);
    } on TypeError {
      malformedRejected = true;
    }
    _require(malformedRejected, '非法字节列表未被公开类型边界拒绝');
    final keyPackage = await bob.keyPackage();
    _require(_same(keyPackage, await bob.keyPackage()), 'KeyPackage精确重试改变');
    _require(
      !_same(await alice.identityKey(), await bob.identityKey()),
      '设备身份重复',
    );
    final welcome = await alice.createGroup(
      conversationId: 'release-group',
      peerAccountId: 'bob',
      peerDeviceId: 'bob-flutter',
      peerIdentityKey: await bob.identityKey(),
      keyPackage: keyPackage,
    );
    await bob.joinGroup(
      conversationId: 'release-group',
      creatorAccountId: 'alice',
      creatorDeviceId: 'alice-flutter',
      creatorIdentityKey: await alice.identityKey(),
      welcome: welcome,
    );
    final message = Uint8List.fromList(utf8.encode('Flutter consumer to peer'));
    final encrypted = await alice.encrypt(plaintext: message);
    _require(!_same(message, encrypted), '密文与明文相同');
    _require(
      _same(message, await bob.decrypt(ciphertext: encrypted)),
      '首方向解密失败',
    );
    final reply = Uint8List.fromList(utf8.encode('Peer to Flutter consumer'));
    _require(
      _same(
        reply,
        await alice.decrypt(ciphertext: await bob.encrypt(plaintext: reply)),
      ),
      '反方向解密失败',
    );
    await bob.close();
    await bob.close();
    var rejected = false;
    try {
      await bob.encrypt(plaintext: message);
    } catch (error) {
      rejected = error.toString().contains('closed; device_poisoned=false');
    }
    _require(rejected, '关闭后操作未拒绝');
  } finally {
    await alice.close();
    await bob.close();
  }
}
