Pod::Spec.new do |s|

  s.name         = "ENCryptor"
  s.version      = "0.0.1"
  s.summary      = "Encryption engine powering Encrypto app"
  s.homepage     = "http://macpaw.com/encrypto"
  s.license      = { :type => "Apache License, Version 2.0", :file => "LICENSE" }
  s.author    = "MacPaw Inc."
  s.social_media_url   = "https://twitter.com/macpaw"
  s.platform     = :osx, "10.9"
  s.source       = { :git => "https://github.com/MacPaw/ENCryptor.git", :tag => "#{s.version}" }
  s.source_files  = "ENCryptor/*.{h,m}"
  s.public_header_files = "ENCryptor/{ENEncryptedArchive,ENArchiveOpener,ENDecryptor,ENEncryptor}.h"
  s.library   = "z"
  s.requires_arc = true

end
