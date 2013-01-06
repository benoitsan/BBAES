//
//  BBAES.h
//  BBAES
//
//  Created by Benoît on 29/12/12.
//  Copyright (c) 2012 Pragmatic Code. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 `BBAES` uses the AES128 algorithm in CBC mode with PKCS#7 padding (128 means the IV has a fixed size of 128-bit).
 This class requires the `Security` framework.
 */

typedef NS_ENUM(NSUInteger, BBAESKeySize) {
    BBAESKeySize128 = 16,
    BBAESKeySize192 = 24,
	BBAESKeySize256 = 32
};

typedef NS_ENUM(NSUInteger, BBAESEncryptionOptions) {
    BBAESEncryptionOptionsIncludeIV = 1 <<  0 // the IV is saved along with the ciphertext (the IV is stored as the first block of the encrypted data).
};

typedef NS_ENUM(NSUInteger, BBAESDataEncoding) {
    BBAESDataEncodingBase64,
    BBAESDataEncodingHex
};

extern NSUInteger const BBAESPBKDF2DefaultIterationsCount;
extern NSUInteger const BBAESSaltDefaultLength;

@interface BBAES : NSObject

/**
 Returns an IV of 16 bytes.
 */
+ (NSData *)randomIV;
+ (NSData *)IVFromString:(NSString *)string;

/**
 Returns count random bytes.
 */
+ (NSData *)randomDataWithLength:(NSUInteger)length;

/**
 Stretchs the key to a given size. 
 The returned value is a hash value of the password. The hash function is MD5 for a 128 bits key and SHA256 for a 256 bits key.
 This method doesn't work for 192 bits key sizes.
 */
+ (NSData *)keyByHashingPassword:(NSString *)password keySize:(BBAESKeySize)keySize;

/**
 Strengthen the password into a cryptographic key.
 The password is salted using PBKDF2. The salt is used to increase its resistance to brute force search.
 The recommanded number of iterations if `BBAESPBKDF2DefaultIterationsCount`.
 The salt is not confidential and can be stored in cleartext.
 */
+ (NSData *)keyBySaltingPassword:(NSString *)password salt:(NSData *)salt keySize:(BBAESKeySize)keySize numberOfIterations:(NSUInteger)numberOfIterations;

/**
 Encrypts a data and returns the encrypted data.
 @param data The data to be encoded.
 @param iv The initialization vector. It must have a fixed size of 16 bytes.
 @param key The AES key. It must have a size of 128, 192, or 256 bits.
 @param options Encryption options.
 */
+ (NSData *)encryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;

/**
 Encrypts a data and returns the encrypted data as a base 64 encoded string.
 See + (NSData *)encryptedDataFromData:iv:key:options: for more informations.
 */
+ (NSString *)encryptedStringFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;

/**
 Decrypts a data and returns the decrypted data.
 @param data The encrypted data.
 @param iv: the IV used to encrypt the data or nil if the encryption uses the `BBAESEncryptionOptionsIncludeIV` parameter.
 @param key The AES key used to encrypt the data. It must have a size of 128, 192, or 256 bits.
 */
+ (NSData *)decryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key;

/**
 Decrypts a data encoded as a base 64 encoded string and returns the decrypted data.
 See + (NSData *)decryptedDataFromData:iv:key: for more informations.
 */
+ (NSData *)decryptedDataFromString:(NSString *)string IV:(NSData *)iv key:(NSData *)key;

+ (NSString *)stringFromData:(NSData *)data encoding:(BBAESDataEncoding)encoding;
+ (NSData *)dataFromString:(NSString *)string encoding:(BBAESDataEncoding)encoding;

@end

@interface NSString (BBAES_NSString)
- (NSString *)bb_AESEncryptedStringForIV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options;
- (NSString *)bb_AESDecryptedStringForIV:(NSData *)iv key:(NSData *)key;
@end



