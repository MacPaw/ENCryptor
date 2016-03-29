# ENCryptor

## Overview
ENCryptor is an engine powering our awesome [Encrypto app](https://itunes.apple.com/us/app/encrypto-encrypt-files-you/id935235287?mt=12), now open source.

## Installation
Preferred way of installation is through CocoaPods

```ruby
pod 'ENCryptor', :git => 'https://github.com/MacPaw/ENCryptor.git'
```
Otherwise, you can build the project and copy ENCryptor.framework to your project.

## Usage
### Opening (viewing hint and preview, checking password)

```objc
self.archiveOpener = [ENArchiveOpener openerWithArchiveURL:...];
self.archiveOpener.delegate = self;

NSString *hint = self.archiveOpener.hint;
...
if ([self.archiveOpener checkPassword:password]) {
	NSImage *preview = self.archiveOpener.preview;
}
```

### Encrypting

```objc
self.encryptor = [ENEncryptor encryptorWithSourceURLs:@[...]];
self.encryptor.delegate = self;

[self.encryptor encryptWithPassword:password hint:hint preview:preview];
...
- (void)encryptor:(ENEncryptor *)encryptor didFinishWithResultURL:(NSURL *)resultURL {
// resultURL now contains resulting .crypto file located somewhere in temporary directory
}
```

### Decrypting

```objc
self.decryptor = [ENDecryptor decryptorWithArchiveURL:resolvedInputURL];
self.decryptor.delegate = self;

[self.decryptor decryptWithPassword:password];
...
- (void)decryptor:(ENDecryptor *)decryptor didFinishWithResultURL:(NSURL *)resultURL {
// resultURL now contains unarchived file or directory somewhere in temporary directory
}
```

## Demo
ENCryptor comes bundled with encrypto-cli as demo, also available for installation through ```homebrew tap```

## Resources
[Crypto File Structure](Crypto%20File%20Structure.md)

## License
ENCryptor is released under Apache License 2.0 License. See LICENSE file for details.