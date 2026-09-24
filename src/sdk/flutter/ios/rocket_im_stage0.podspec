Pod::Spec.new do |s|
  s.name = 'rocket_im_stage0'
  s.version = '0.1.0-stage0.1'
  s.summary = 'Rocket-IM Stage 0 local release package.'
  s.description = 'Precompiled in-memory SDK experiment; no Rust toolchain at app build time.'
  s.homepage = 'https://example.invalid/rocket-im-stage0'
  s.license = { :type => 'Local validation only' }
  s.author = 'Rocket-IM'
  s.source = { :path => '.' }
  s.platform = :ios, '13.0'
  s.dependency 'Flutter'
  s.vendored_frameworks = 'Frameworks/RocketStage0Flutter.xcframework'
  s.static_framework = true
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  # 打包器从实际生成Dart与固定FRB运行时提取完整Rust lookup符号。
  # 由CocoaPods常规-framework链接静态Framework，精确保留动态调用入口。
  s.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) @ROCKET_IOS_RETAIN_SYMBOLS@'
  }
  s.swift_version = '5.0'
end
