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

static NSData * digest(NSData *data, unsigned char *(*cc_digest)(const void *, CC_LONG, unsigned char *), CC_LONG digestLength) {
	unsigned char md[digestLength];
    memset(md, 0, sizeof(md));
	cc_digest([data bytes], (CC_LONG)[data length], md);
	return [NSData dataWithBytes:md length:sizeof(md)];
}

//static NSData * SHA1Hash(NSData* data) {
//	return digest(data, CC_SHA1, CC_SHA1_DIGEST_LENGTH);
//}

static NSData * MD5Hash(NSData* data) {
	return digest(data, CC_MD5, CC_MD5_DIGEST_LENGTH);
}

static NSData * SHA256Hash(NSData* data) {
	return digest(data, CC_SHA256, CC_SHA256_DIGEST_LENGTH);
}

static NSData * dataFromBase64EncodedString(NSString* string) {
	// Copyright (C) 2012 Charcoal Design (https://github.com/nicklockwood/Base64)
    const char lookup[] =
    {
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 62, 99, 99, 99, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 99, 99, 99, 99, 99, 99,
        99,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 99, 99, 99, 99, 99,
        99, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 99, 99, 99, 99, 99
    };
    
    NSData *inputData = [string dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    long long inputLength = [inputData length];
    const unsigned char *inputBytes = [inputData bytes];
    
    long long maxOutputLength = (inputLength / 4 + 1) * 3;
    NSMutableData *outputData = [NSMutableData dataWithLength:(NSUInteger)maxOutputLength];
    unsigned char *outputBytes = (unsigned char *)[outputData mutableBytes];
	
    int accumulator = 0;
    long long outputLength = 0;
    unsigned char accumulated[] = {0, 0, 0, 0};
    for (long long i = 0; i < inputLength; i++) {
        unsigned char decoded = lookup[inputBytes[i] & 0x7F];
        if (decoded != 99) {
            accumulated[accumulator] = decoded;
            if (accumulator == 3) {
                outputBytes[outputLength++] = (accumulated[0] << 2) | (accumulated[1] >> 4);
                outputBytes[outputLength++] = (accumulated[1] << 4) | (accumulated[2] >> 2);
                outputBytes[outputLength++] = (accumulated[2] << 6) | accumulated[3];
            }
            accumulator = (accumulator + 1) % 4;
        }
    }
    
    if (accumulator > 0) outputBytes[outputLength] = (accumulated[0] << 2) | (accumulated[1] >> 4);
    if (accumulator > 1) outputBytes[++outputLength] = (accumulated[1] << 4) | (accumulated[2] >> 2);
    if (accumulator > 2) outputLength++;
    
    outputData.length = (CFIndex)outputLength;
    return outputLength? outputData: nil;
}

static NSString * base64EncodedStringFromData(NSData* data) {
	// Copyright (C) 2012 Charcoal Design (https://github.com/nicklockwood/Base64)
    const NSUInteger wrapWidth = 0;
    const char lookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    long long inputLength = [data length];
    const unsigned char *inputBytes = [data bytes];
    
    long long maxOutputLength = (inputLength / 3 + 1) * 4;
    maxOutputLength += wrapWidth? (maxOutputLength / wrapWidth) * 2: 0;
    unsigned char *outputBytes = (unsigned char *)malloc((size_t)maxOutputLength);
    
    long long i;
    long long outputLength = 0;
    for (i = 0; i < inputLength - 2; i += 3) {
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
        outputBytes[outputLength++] = lookup[((inputBytes[i + 1] & 0x0F) << 2) | ((inputBytes[i + 2] & 0xC0) >> 6)];
        outputBytes[outputLength++] = lookup[inputBytes[i + 2] & 0x3F];
        
        if (wrapWidth && (outputLength + 2) % (wrapWidth + 2) == 0) {
            outputBytes[outputLength++] = '\r';
            outputBytes[outputLength++] = '\n';
        }
    }
    
    if (i == inputLength - 2) {
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[((inputBytes[i] & 0x03) << 4) | ((inputBytes[i + 1] & 0xF0) >> 4)];
        outputBytes[outputLength++] = lookup[(inputBytes[i + 1] & 0x0F) << 2];
        outputBytes[outputLength++] =   '=';
    }
    else if (i == inputLength - 1) {
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0xFC) >> 2];
        outputBytes[outputLength++] = lookup[(inputBytes[i] & 0x03) << 4];
        outputBytes[outputLength++] = '=';
        outputBytes[outputLength++] = '=';
    }
    outputBytes = realloc(outputBytes, (size_t)outputLength);
    NSString *result = [[NSString alloc] initWithBytesNoCopy:outputBytes length:(NSUInteger)outputLength encoding:NSASCIIStringEncoding freeWhenDone:YES];
	
    return (outputLength >= 4) ? result: nil;
}

static NSString * hexStringFromData(NSData* data){
	NSUInteger capacity = data.length * 2;
	NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:capacity];
	const unsigned char *dataBuffer = data.bytes;
	NSInteger i;
	for (i=0; i<data.length; ++i) {
		[stringBuffer appendFormat:@"%02lx", (long)dataBuffer[i]];
	}
	return [[NSString stringWithString:stringBuffer]lowercaseString];
}

static NSData * dataFromHexString(NSString * hex) {
	NSMutableData *data = [NSMutableData new];
	for (NSUInteger i=0; i<hex.length; i+=2) {
		char high = (char)[hex characterAtIndex:i];
		char low = (char)[hex characterAtIndex:i+1];
		char bchars[3] = {high, low, '\0'};
		UInt8 byte = strtol(bchars, NULL, 16);
		[data appendBytes:&byte length:1];
	}
	return [NSData dataWithData:data];
}

//  The key is derived from the password using PBKDF2 with 10000 iterations like Apple does since iOS4  (http://en.wikipedia.org/wiki/PBKDF2).
NSUInteger const BBAESPBKDF2DefaultIterationsCount = 10000;
NSUInteger const BBAESSaltDefaultLength = 16; //recommandations suggest at least 8 bytes http://security.stackexchange.com/questions/11221/how-big-salt-should-be?rq=1

@implementation BBAES {}

#pragma mark - IV Generation

+ (NSData *)randomIV {
	return [BBAES randomDataWithLength: kCCBlockSizeAES128];
}

+ (NSData *)IVFromString:(NSString *)string {
	return MD5Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // MD5 produces a 16-bytes hash value
}

#pragma mark - Password Stretching

+ (NSData *)randomDataWithLength:(NSUInteger)length {
	NSMutableData *data = [NSMutableData dataWithLength:length];
    SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    return data;
}

+ (NSData *)keyByHashingPassword:(NSString *)string keySize:(BBAESKeySize)keySize {
	NSParameterAssert(string);
	
	NSData *retData = nil;
	if (keySize == BBAESKeySize128) {
		retData = MD5Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // MD5 produces a 128 bits hash value
	}
	if (keySize == BBAESKeySize256) {
		retData = SHA256Hash([string dataUsingEncoding:NSUTF8StringEncoding]); // SHA256 produces a 256 bits hash value
	}
	else {
		[NSException exceptionWithName:NSInternalInconsistencyException reason:@"The key size must be `BBAESKeySize128` or `BBAESKeySize256`." userInfo:nil];
	}
	return retData;
}

+ (NSData *)keyBySaltingPassword:(NSString *)password salt:(NSData *)salt keySize:(BBAESKeySize)keySize numberOfIterations:(NSUInteger)numberOfIterations {
	NSParameterAssert(password);
	NSParameterAssert(salt);
	
	NSMutableData *derivedKey = [NSMutableData dataWithLength:keySize];
	
	// The password needs to be converted from UTF-8 encoding to iso 8859-1 encoding.
	// http://stackoverflow.com/questions/4553388/how-to-convert-utf8-encoding-to-iso-8859-1-encoding
	char converted[([password length] + 1)];
	[password getCString:converted maxLength:([password length] + 1) encoding: NSISOLatin1StringEncoding];

	int result = CCKeyDerivationPBKDF(kCCPBKDF2, converted, ([password length] + 1), salt.bytes, salt.length, kCCPRFHmacAlgSHA1, (uint)numberOfIterations, derivedKey.mutableBytes, derivedKey.length);
	NSAssert(result == kCCSuccess, @"Fail to create the salted key");
	return [derivedKey copy];
}

#pragma mark - AES Crypting

+ (NSData *)encryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options {
	NSParameterAssert(data);
	NSParameterAssert(key);
	NSParameterAssert(iv);
	NSAssert(key.length==16 || key.length==24 || key.length==32, @"AES must have a key size of 128, 192, or 256 bits.");
	NSAssert1(iv.length==kCCBlockSizeAES128, @"AES must have a fixed IV size of %d-bytes regardless key size.",kCCBlockSizeAES128);
	
	//NSLog(@"data %@",hexStringFromData(data));
	//NSLog(@"key %@",hexStringFromData(key));
	//NSLog(@"iv %@",hexStringFromData(iv));
	
	NSData *encryptedData = [BBAES bb_runAES128CryptorWithOperation:kCCEncrypt data:data iv:iv key:key];
	NSData *retValue;
	if (options & BBAESEncryptionOptionsIncludeIV) {
		NSMutableData *mutableData = [NSMutableData dataWithData:iv];
		[mutableData appendData:encryptedData];
		retValue = [mutableData copy];
	}
	else {
		retValue = encryptedData;
	}
	
    return retValue;
}

+ (NSString *)encryptedStringFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options {
	NSData *encryptedData = [BBAES encryptedDataFromData:data IV:iv key:key options:options];
	NSString *retValue = base64EncodedStringFromData(encryptedData);
	return retValue;
}

+ (NSData *)decryptedDataFromData:(NSData *)data IV:(NSData *)iv key:(NSData *)key {
	NSParameterAssert(data);
	NSParameterAssert(key);
	NSAssert(key.length==16 || key.length==24 || key.length==32, @"AES must have a key size of 128, 192, or 256 bits.");
	NSAssert1(!iv || iv.length==kCCBlockSizeAES128, @"AES must have a fixed IV size of %d-bytes regardless key size.",kCCBlockSizeAES128);
	
	NSData *encryptedData;
    if (!iv) {
		const NSUInteger ivLength = kCCBlockSizeAES128;
		iv = [data subdataWithRange:NSMakeRange(0,ivLength)];
		encryptedData = [data subdataWithRange:NSMakeRange(ivLength,[data length]-ivLength)];
	}
	else {
		encryptedData = data;
	}
	
	NSData *decryptedData = [BBAES bb_runAES128CryptorWithOperation:kCCDecrypt data:encryptedData iv:iv key:key];
	
	return decryptedData;
}

+ (NSData *)decryptedDataFromString:(NSString *)string IV:(NSData *)iv key:(NSData *)key {
	NSData *data = dataFromBase64EncodedString(string);
	NSData *decryptedData = [BBAES decryptedDataFromData:data IV:iv key:key];
	return decryptedData;
}

#pragma mark - Data Encoding

+ (NSString *)stringFromData:(NSData *)data encoding:(BBAESDataEncoding)encoding {
	if (encoding == BBAESDataEncodingBase64) {
		return base64EncodedStringFromData(data);
	}
	else if (encoding == BBAESDataEncodingHex) {
		return hexStringFromData(data);
	}
	NSAssert(NO, @"Unknown encoding");
	return nil;
}

+ (NSData *)dataFromString:(NSString *)string encoding:(BBAESDataEncoding)encoding {
	if (encoding == BBAESDataEncodingBase64) {
		return dataFromBase64EncodedString(string);
	}
	else if (encoding == BBAESDataEncodingHex) {
		return dataFromHexString(string);
	}
	NSAssert(NO, @"Unknown encoding");
	return nil;
}

#pragma mark - Private Methods

+ (NSData *)bb_runAES128CryptorWithOperation:(CCOperation)operation data:(NSData *)data iv:(NSData *)iv key:(NSData *)key {
	
	CCCryptorRef cryptor = NULL;
	
	// 1. Create a cryptographic context.
	CCCryptorStatus status = CCCryptorCreate(operation, kCCAlgorithmAES128, kCCOptionPKCS7Padding, [key bytes], [key length], [iv bytes], &cryptor );
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

- (NSString *)bb_AESEncryptedStringForIV:(NSData *)iv key:(NSData *)key options:(BBAESEncryptionOptions)options {
	return [BBAES encryptedStringFromData:[self dataUsingEncoding:NSUTF8StringEncoding] IV:iv key:key options:options];
}

- (NSString *)bb_AESDecryptedStringForIV:(NSData *)iv key:(NSData *)key {
	return [[NSString alloc] initWithData:[BBAES decryptedDataFromString:self IV:iv key:key] encoding:NSUTF8StringEncoding];
}

@end


