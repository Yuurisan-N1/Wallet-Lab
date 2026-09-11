Pod::Spec.new do |s|
  s.name         = "react-native-ultrafast-secp256k1"
  s.version      = "1.0.0"
  s.summary      = "React Native bindings for UltrafastSecp256k1"
  s.homepage     = "https://github.com/UltrafastSecp256k1/react-native-ultrafast-secp256k1"
  s.license      = "MIT"
  s.author       = "UltrafastSecp256k1"
  s.source       = { :git => "https://github.com/UltrafastSecp256k1/react-native-ultrafast-secp256k1.git", :tag => s.version }

  s.platforms    = { :ios => "15.0" }
  s.source_files = "ios/**/*.{h,m,mm}"

  s.dependency "React-Core"

  # Link the C shared library
  s.libraries = "ultrafast_secp256k1"
  s.xcconfig  = {
    "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/../../../bindings/c_api\"",
    "LIBRARY_SEARCH_PATHS" => "\"$(PODS_ROOT)/../../../bindings/c_api/build\""
  }
end
