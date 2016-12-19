# BBAES

BBAES is a lightweight [AES](http://en.wikipedia.org/wiki/Advanced_Encryption_Standard "AES on Wikipedia") Encryption Class for iOS and OS X. It uses the encryption APIs of the CommonCrypto library. It provides methods to handle password stretching and generating IV (Initialization Vector). 

BBAES uses the AES128 algorithm in CBC mode with PKCS#7 padding (128 means the IV has a fixed size of 128-bit). BBAES supports key lengths of 128, 192 and 256 bits.

## Requirements

Earliest supported deployment target - iOS 8.0 / Mac OS 10.10

BBAES uses ARC.

## Installation

* Drag the `BBAES.h` and `BBAES.m` class files into your project. 
* Add the Apple Security framework `Security.framework`.

## Documentation

The header file `BBAES.h` is documented. Have also a look at the demo and unit tests to see how to use the class.

## Key sizes

BBAES supports cryptographic keys of 128, 192, and 256 bits to encrypt and decrypt data.

``` objective-c
typedef NS_ENUM(NSUInteger, BBAESKeySize) {
    BBAESKeySize128 = 16,
    BBAESKeySize192 = 24,
	BBAESKeySize256 = 32
};
```

## Key Stretching Methods

Use these methods to generate an AES key:

    + (NSData *)keyByHashingPassword:(NSString *)password keySize:(BBAESKeySize)keySize;
    + (NSData *)keyBySaltingPassword:(NSString *)password salt:(NSData *)salt keySize:(BBAESKeySize)keySize numberOfIterations:(NSUInteger)numberOfIterations;
    + (NSData *)randomDataWithLength:(NSUInteger)length;
    
The salt is used so that the same password does not generate the same key. Salts are used in cryptographic hashing in order to eliminate the rainbow table method of cracking.

## Encrypting Methods

Use these methods to encrypt a data:

    + (NSData *)encryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;
    
Encrypts a data and returns the encrypted data.
    
    + (NSString *)encryptedStringFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;
    
Encrypts a data and returns the encrypted data as a base 64 encoded string.
     
    + (NSData *)randomIV;
    + (NSData *)IVFromString:(NSString *)string;
    
returns an IV. 

A random IV (initialization vector) ensures that the same plaintext does not produce the same ciphertext.

## Decrypting Methods

Use these methods to decrypt a data:

    + (NSData *)decryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key;
    
Decrypts a data and returns the decrypted data.
     
    + (NSData *)decryptedDataFromString:(NSString *)string IV:(NSData *)iv key:(NSData *)key;

Decrypts a data encoded as a base 64 encoded string and returns the decrypted data.

## NSString Category

Category that provide methods to easily encode strings.

``` objective-c
@interface NSString (BBAES_NSString)
- (NSString *)bb_AESEncryptedStringForIV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;
- (NSString *)bb_AESDecryptedStringForIV:(NSData *)iv key:(NSData *)key;
@end
```
     
## Example

``` objective-c
NSData* salt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
NSData *key = [BBAES keyBySaltingPassword:@"password" salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];

NSString *secretMessage = @"My secret message.";
NSLog(@"Original message: %@", secretMessage);

NSString *encryptedString = [secretMessage bb_AESEncryptedStringForIV:[BBAES randomIV] key:key options:BBAESEncryptionOptionsIncludeIV];
NSLog(@"Encrypted message: %@", encryptedString);

NSString *decryptedMessage = [encryptedString bb_AESDecryptedStringForIV:nil key:key];
NSLog(@"Decrypted message: %@", decryptedMessage);
```

## Creator

[Benoît Bourdon](https://github.com/benoitsan) ([@benoitsan](https://twitter.com/benoitsan)).

## License

BBAES is available under the MIT license. See the LICENSE file for more info.