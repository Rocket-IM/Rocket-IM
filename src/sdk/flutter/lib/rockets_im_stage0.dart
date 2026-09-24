/// 阶段0内存设备API。密码状态由Rust对象独立持有；无网络、持久化或业务认证。
library;

import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'src/rust/api.dart' as native;
import 'src/rust/frb_generated.dart';

const packageVersion = '0.1.0-stage0.1';
Future<void>? _initialization;

/// 加载包内二进制。版本或加载失败在当前进程保持失败，不尝试其他路径。
/// expectedVersion可进一步要求精确版本，不能替代包本身的版本检查。
Future<void> initialize({String expectedVersion = packageVersion}) {
  final initialization = _initialization ??= _load(expectedVersion);
  return initialization.then((_) {
    if (expectedVersion != packageVersion) {
      throw StateError('调用方要求的 SDK 版本与发布包不匹配');
    }
  });
}

Future<void> _load(String expectedVersion) async {
  final ExternalLibrary library;
  if (Platform.isAndroid) {
    library = ExternalLibrary.open('librockets_stage0_flutter.so');
  } else if (Platform.isIOS) {
    // 静态XCFramework通过podspec链接；不尝试其他库或路径。
    library = ExternalLibrary.process(iKnowHowToUseIt: true);
  } else {
    throw UnsupportedError('此包只支持 Android 和 iOS 发布目标');
  }
  await RustLib.init(externalLibrary: library);
  final actualVersion = native.sdkVersion();
  if (actualVersion != packageVersion || actualVersion != expectedVersion) {
    throw StateError('SDK 原生库、Dart 包与调用方要求的版本不匹配');
  }
}

/// 在成功版本检查后创建独立内存设备。失败不返回半初始化对象。
Future<Stage0Device> newDevice({
  required String serviceId,
  required String accountId,
  required String deviceId,
}) async {
  await initialize();
  return Stage0Device._(
    await native.newDevice(
      serviceId: serviceId,
      accountId: accountId,
      deviceId: deviceId,
    ),
  );
}

/// 不导出生成绑定。所有字节入口要求Uint8List，避免List<int>静默截断。
/// 异步方法由FRB桥接，调用顺序与状态由Rust维护。close幂等关闭密码状态。
class Stage0Device {
  Stage0Device._(this._inner);
  final native.Stage0Device _inner;

  Future<Uint8List> identityKey() => _inner.identityKey();
  Future<Uint8List> keyPackage() => _inner.keyPackage();
  Future<Uint8List> createGroup({
    required String conversationId,
    required String peerAccountId,
    required String peerDeviceId,
    required Uint8List peerIdentityKey,
    required Uint8List keyPackage,
  }) => _inner.createGroup(
    conversationId: conversationId,
    peerAccountId: peerAccountId,
    peerDeviceId: peerDeviceId,
    peerIdentityKey: peerIdentityKey,
    keyPackage: keyPackage,
  );
  Future<void> joinGroup({
    required String conversationId,
    required String creatorAccountId,
    required String creatorDeviceId,
    required Uint8List creatorIdentityKey,
    required Uint8List welcome,
  }) => _inner.joinGroup(
    conversationId: conversationId,
    creatorAccountId: creatorAccountId,
    creatorDeviceId: creatorDeviceId,
    creatorIdentityKey: creatorIdentityKey,
    welcome: welcome,
  );
  Future<Uint8List> encrypt({required Uint8List plaintext}) =>
      _inner.encrypt(plaintext: plaintext);
  Future<Uint8List> decrypt({required Uint8List ciphertext}) =>
      _inner.decrypt(ciphertext: ciphertext);
  Future<void> close() => _inner.close();
}
