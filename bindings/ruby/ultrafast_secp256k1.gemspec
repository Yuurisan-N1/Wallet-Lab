Gem::Specification.new do |s|
  s.name        = 'ultrafast_secp256k1'
  s.version     = '1.0.0'
  s.summary     = 'Ruby FFI bindings for UltrafastSecp256k1'
  s.description = 'High-performance secp256k1 ECC: ECDSA, Schnorr, ECDH, recovery, BIP-32, Taproot, addresses.'
  s.authors     = ['UltrafastSecp256k1']
  s.license     = 'MIT'
  s.homepage    = 'https://github.com/UltrafastSecp256k1/ruby-secp256k1'

  s.required_ruby_version = '>= 3.0'
  s.add_dependency 'ffi', '~> 1.15'

  s.files = Dir['lib/**/*.rb'] + ['README.md']
end
