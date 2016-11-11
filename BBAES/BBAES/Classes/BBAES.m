//
//  BBAES.m
//  BBAES
//
//  Created by Benoît on 29/12/12.
//  Copyright (c) 2012 Pragmatic Code. All rights reserved.
//

#import "BBAES.h"

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>
#import <Security/SecRandom.h>

#if !__has_feature(objc_arc)
#error BBAES must be built with ARC.
// You can turn on ARC for only BBAES files by adding -fobjc-arc to the build phase for each of its files.
#endif

static NSData *digest(NSData *data, unsigned char *(*cc_digest)(const void *, CC_LONG, unsigned char *), CC_LONG digestLength)
{
	unsigned char md[digestLength];
	memset(md, 0, sizeof(md));
	cc_digest([data bytes], (CC_LONG)[data length], md);
	return [NSData dataWithBytes:md length:sizeof(md)];
}

//static NSData * SHA1Hash(NSData* data) {
//	return digest(data, CC_SHA1, CC_SHA1_DIGEST_LENGTH);
//}

static NSData *MD5Hash(NSData *data)
{
	return digest(data, CC_MD5, CC_MD5_DIGEST_LENGTH);
}

static NSData *SHA256Hash(NSData *data)
{
	return digest(data, CC_SHA256, CC_SHA256_DIGEST_LENGTH);
}

static NSData *dataFromBase64EncodedString(NSString *string)
{
	return [[NSData alloc] initWithBase64EncodedString:string options:0];
}

static NSString *base64EncodedStringFromData(NSData *data)
{
	return [data base64EncodedStringWithOptions:0];
}

static NSString *hexStringFromData(NSData *data)
{
	NSUInteger capacity = data.length * 2;
	NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:capacity];
	const unsigned char *dataBuffer = data.bytes;
	NSInteger i;
	for (i = 0; i < data.length; ++i) {
		[stringBuffer appendFormat:@"%02lx", (long)dataBuffer[i]];
	}
	return [[NSString stringWithString:stringBuffer] lowercaseString];
}

static NSData *dataFromHexString(NSString *hex)
{
	NSMutableData *data = [NSMutableData new];
	for (NSUInteger i = 0; i < hex.length; i += 2) {
		char high = (char)[hex characterAtIndex:i];
		char low = (char)[hex characterAtIndex:i + 1];
		char bchars[3] = {high, low, '\0'};
		UInt8 byte = strtol(bchars, NULL, 16);
		[data appendBytes:&byte length:1];
	}
	return [NSData dataWithData:data];
}

//  The key is derived from the password using PBKDF2 with 10000 iterations like Apple does since iOS4  (http://en.wikipedia.org/wiki/PBKDF2).
NSUInteger const BBAESPBKDF2DefaultIterationsCount = 10000;
NSUInteger const BBAESSaltDefaultLength = 16; //recommandations suggest at least 8 bytes http://security.stackexchange.com/questions/11221/how-big-salt-should-be?rq=1

@implementation BBAES {
}

#pragma mark - IV Generation

+ (NSData *)randomIV
{
	return [BBAES randomDataWithLength:kCCBlockSizeAES128];
}

+ (NSData *)IVFromString:(NSString *)string
{
	return MD5Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // MD5 produces a 16-bytes hash value
}

#pragma mark - Password Stretching

+ (NSData *)randomDataWithLength:(NSUInteger)length
{
	NSMutableData *data = [NSMutableData dataWithLength:length];
	int res __attribute__((unused)) = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
	return data;
}

+ (NSData *)keyByHashingPassword:(NSString *)string keySize:(BBAESKeySize)keySize
{
	NSParameterAssert(string);

	NSData *retData = nil;
	if (keySize == BBAESKeySize128) {
		retData = MD5Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // MD5 produces a 128 bits hash value
	}
	if (keySize == BBAESKeySize256) {
		retData = SHA256Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // SHA256 produces a 256 bits hash value
	} else {
		[NSException exceptionWithName:NSInternalInconsistencyException reason:@"The key size must be `BBAESKeySize128` or `BBAESKeySize256`." userInfo:nil];
	}
	return retData;
}

+ (NSData *)keyBySaltingPassword:(NSString *)password salt:(NSData *)salt keySize:(BBAESKeySize)keySize numberOfIterations:(NSUInteger)numberOfIterations
{
	NSParameterAssert(password);
	NSParameterAssert(salt);

	NSMutableData *derivedKey = [NSMutableData dataWithLength:keySize];

	// The password needs to be converted from UTF-8 encoding to iso 8859-1 encoding.
	// http://stackoverflow.com/questions/4553388/how-to-convert-utf8-encoding-to-iso-8859-1-encoding
	char converted[([password length] + 1)];
	[password getCString:converted maxLength:([password length] + 1)encoding:NSISOLatin1StringEncoding];

	__unused int result = CCKeyDerivationPBKDF(kCCPBKDF2, converted, ([password length] + 1), salt.bytes, salt.length, kCCPRFHmacAlgSHA1, (uint)numberOfIterations, derivedKey.mutableBytes, derivedKey.length);
	NSAssert(result == kCCSuccess, @"Fail to create the salted key");
	return [derivedKey copy];
}

#pragma mark - AES Crypting

+ (NSData *)encryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options
{
	NSParameterAssert(data);
	NSParameterAssert(key);
	NSParameterAssert(iv);
	NSAssert(key.length == 16 || key.length == 24 || key.length == 32, @"AES must have a key size of 128, 192, or 256 bits.");
	NSAssert1(iv.length == kCCBlockSizeAES128, @"AES must have a fixed IV size of %d-bytes regardless key size.", kCCBlockSizeAES128);

	//NSLog(@"data %@",hexStringFromData(data));
	//NSLog(@"key %@",hexStringFromData(key));
	//NSLog(@"iv %@",hexStringFromData(iv));

	NSData *encryptedData = [BBAES bb_runAES128CryptorWithOperation:kCCEncrypt data:data iv:iv key:key];
	NSData *retValue;
	if (options & BBAESEncryptionOptionsIncludeIV) {
		NSMutableData *mutableData = [NSMutableData dataWithData:iv];
		[mutableData appendData:encryptedData];
		retValue = [mutableData copy];
	} else {
		retValue = encryptedData;
	}

	return retValue;
}

+ (NSString *)encryptedStringFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options
{
	NSData *encryptedData = [BBAES encryptedDataFromData:data IV:iv key:key options:options];
	NSString *retValue = base64EncodedStringFromData(encryptedData);
	return retValue;
}

+ (NSData *)decryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key
{
	NSParameterAssert(data);
	NSParameterAssert(key);
	NSAssert(key.length == 16 || key.length == 24 || key.length == 32, @"AES must have a key size of 128, 192, or 256 bits.");
	NSAssert1(!iv || iv.length == kCCBlockSizeAES128, @"AES must have a fixed IV size of %d-bytes regardless key size.", kCCBlockSizeAES128);

	NSData *encryptedData;
	if (!iv) {
		const NSUInteger ivLength = kCCBlockSizeAES128;
		iv = [data subdataWithRange:NSMakeRange(0, ivLength)];
		encryptedData = [data subdataWithRange:NSMakeRange(ivLength, [data length] - ivLength)];
	} else {
		encryptedData = data;
	}

	NSData *decryptedData = [BBAES bb_runAES128CryptorWithOperation:kCCDecrypt data:encryptedData iv:iv key:key];

	return decryptedData;
}

+ (NSData *)decryptedDataFromString:(NSString *)string IV:(NSData *)iv key:(NSData *)key
{
	NSData *data = dataFromBase64EncodedString(string);
	NSData *decryptedData = [BBAES decryptedDataFromData:data IV:iv key:key];
	return decryptedData;
}

#pragma mark - Data Encoding

+ (NSString *)stringFromData:(NSData *)data encoding:(BBAESDataEncoding)encoding
{
	if (encoding == BBAESDataEncodingBase64) {
		return base64EncodedStringFromData(data);
	} else if (encoding == BBAESDataEncodingHex) {
		return hexStringFromData(data);
	}
	NSAssert(NO, @"Unknown encoding");
	return nil;
}

+ (NSData *)dataFromString:(NSString *)string encoding:(BBAESDataEncoding)encoding
{
	if (encoding == BBAESDataEncodingBase64) {
		return dataFromBase64EncodedString(string);
	} else if (encoding == BBAESDataEncodingHex) {
		return dataFromHexString(string);
	}
	NSAssert(NO, @"Unknown encoding");
	return nil;
}

#pragma mark - Private Methods

+ (NSData *)bb_runAES128CryptorWithOperation:(CCOperation)operation data:(NSData *)data iv:(NSData *)iv key:(NSData *)key
{
	CCCryptorRef cryptor = NULL;

	// 1. Create a cryptographic context.
	CCCryptorStatus status = CCCryptorCreate(operation, kCCAlgorithmAES128, kCCOptionPKCS7Padding, [key bytes], [key length], [iv bytes], &cryptor);
	NSAssert(status == kCCSuccess, @"Failed to create a cryptographic context.");

	NSMutableData *retData = [NSMutableData new];

	// 2. Encrypt or decrypt data.
	NSMutableData *buffer = [NSMutableData data];
	[buffer setLength:CCCryptorGetOutputLength(cryptor, [data length], true)]; // We'll reuse the buffer in -finish

	size_t dataOutMoved;
	status = CCCryptorUpdate(cryptor, data.bytes, data.length, buffer.mutableBytes, buffer.length, &dataOutMoved);
	NSAssert(status == kCCSuccess, @"Failed to encrypt or decrypt data");
	[retData appendData:[buffer subdataWithRange:NSMakeRange(0, dataOutMoved)]];

	// 3. Finish the encrypt or decrypt operation.
	status = CCCryptorFinal(cryptor, buffer.mutableBytes, buffer.length, &dataOutMoved);
	NSAssert(status == kCCSuccess, @"Failed to finish the encrypt or decrypt operation");
	[retData appendData:[buffer subdataWithRange:NSMakeRange(0, dataOutMoved)]];

	CCCryptorRelease(cryptor);

	return [retData copy];
}

@end

#pragma mark - NSString Category

@implementation NSString (BBAES_NSString)

- (NSString *)bb_AESEncryptedStringForIV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options
{
	return [BBAES encryptedStringFromData:[self dataUsingEncoding:NSUTF8StringEncoding] IV:iv key:key options:options];
}

- (NSString *)bb_AESDecryptedStringForIV:(NSData *)iv key:(NSData *)key
{
	return [[NSString alloc] initWithData:[BBAES decryptedDataFromString:self IV:iv key:key] encoding:NSUTF8StringEncoding];
}

@end
