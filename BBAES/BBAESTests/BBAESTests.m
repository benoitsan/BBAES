//
//  BBAESTests.m
//  BBAESTests
//
//  Created by Benoît on 28/12/13.
//  Copyright (c) 2013 Pragmatic Code. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "BBAES.h"

@interface BBAESTests : XCTestCase

@end

@implementation BBAESTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testIV {
	NSData *iv1 = [BBAES randomIV];
	XCTAssertTrue(iv1.length == 16, @"the IV must have a size of 16 bytes");
	
	NSData *iv2 = [BBAES randomIV];
	XCTAssertFalse([iv1 isEqualToData:iv2], @"IVs must be unique");
	
	
	iv1 = [BBAES IVFromString:@"anIV"];
	XCTAssertTrue(iv1.length == 16, @"the IV must have a size of 16 bytes");
	
	iv2 = [BBAES IVFromString:@"anIV"];
	XCTAssertTrue([iv1 isEqualToData:iv2], @"IVs with the same string must be equal");
}

- (void)testRandomData {
	NSData *salt1 = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	XCTAssertTrue(salt1.length == BBAESSaltDefaultLength, @"Salt size is incorrect");
    
	NSData *salt2 = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	XCTAssertFalse([salt1 isEqualToData:salt2], @"salts must be unique");
}

- (void)testKeyHashing {
	NSData *hashedKey;
	NSString *key = @"My Secret Key";
	
	hashedKey = [BBAES keyByHashingPassword:key keySize:BBAESKeySize128];
	XCTAssertTrue(hashedKey.length==BBAESKeySize128, @"Size of hashed key is wrong.");
	
	XCTAssertNoThrow([BBAES keyByHashingPassword:key keySize:BBAESKeySize192], @"The function shoulnd't support a hash of 24 bits");
	
	hashedKey = [BBAES keyByHashingPassword:key keySize:BBAESKeySize256];
	XCTAssertTrue(hashedKey.length==BBAESKeySize256, @"Size of hashed key is wrong.");
}

- (void)testPasswordSalting {
	NSData *hashedKey;
	NSString *password = @"My Secret Key";
	NSData *salt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	XCTAssertTrue(hashedKey.length==BBAESKeySize128, @"Size of hashed key is wrong.");
	
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	XCTAssertTrue(hashedKey.length==BBAESKeySize256, @"Size of hashed key is wrong.");
	
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	XCTAssertTrue(hashedKey.length==BBAESKeySize256, @"Size of hashed key is wrong.");
	
	XCTAssertTrue([[BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount]isEqualToData:
                  [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount]], @"keys should be identical.");
	
	NSData* salt2 = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	
	XCTAssertFalse([[BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount]isEqualToData:
                   [BBAES keyBySaltingPassword:password salt:salt2 keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount]], @"keys with different salts should be different.");
}

- (void)testStringEncryption {
	NSString *key = @"My Secret Key";
	NSString *string = @"My Secret Message";
	NSData *hashedKey = [BBAES keyByHashingPassword:key keySize:BBAESKeySize256];
	
	NSString *encrypt = [string bb_AESEncryptedStringForIV:[BBAES randomIV] key:hashedKey options:BBAESEncryptionOptionsIncludeIV];
	NSString *decrypt = [encrypt bb_AESDecryptedStringForIV:nil key:hashedKey];
	XCTAssertTrue([string isEqualToString:decrypt], @"the input and decrypted strings must be equal");
	
	NSData *iv = [BBAES randomIV];
	encrypt = [string bb_AESEncryptedStringForIV:iv key:hashedKey options:0];
	decrypt = [encrypt bb_AESDecryptedStringForIV:iv key:hashedKey];
	XCTAssertTrue([string isEqualToString:decrypt], @"the input and decrypted strings must be equal");
	
	XCTAssertFalse([[string bb_AESEncryptedStringForIV:[BBAES randomIV] key:hashedKey options:0] isEqualToString:
				   [string bb_AESEncryptedStringForIV:[BBAES randomIV] key:hashedKey options:0]],@"cipher with 2 different IV should be different");
	
	XCTAssertFalse([[string bb_AESEncryptedStringForIV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0] isEqualToString:
				   [string bb_AESEncryptedStringForIV:[BBAES IVFromString:@"iv2"] key:hashedKey options:0]], @"cipher with 2 different IV (strings) should be different");
	
	XCTAssertTrue([[string bb_AESEncryptedStringForIV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0] isEqualToString:
				  [string bb_AESEncryptedStringForIV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0]], @"cipher with the same IV should be equal");
}

- (void)testDataEncryption {
	NSString *key = @"My Secret Key";
	NSData *data = [@"My Secret Message" dataUsingEncoding:NSUTF8StringEncoding];
	NSData *hashedKey = [BBAES keyByHashingPassword:key keySize:BBAESKeySize256];
	
	NSData *encrypt = [BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:BBAESEncryptionOptionsIncludeIV];
	NSData *decrypt = [BBAES decryptedDataFromData:encrypt IV:nil key:hashedKey];
	XCTAssertTrue([data isEqualToData:decrypt], @"the input and decrypted data must be equal");
    
	NSData *iv = [BBAES randomIV];
	encrypt = [BBAES encryptedDataFromData:data IV:iv key:hashedKey options:0];
	decrypt = [BBAES decryptedDataFromData:encrypt IV:iv key:hashedKey];
	XCTAssertTrue([data isEqualToData:decrypt], @"the input and decrypted data must be equal");
	
	XCTAssertFalse([[BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:0] isEqualToData:
				   [BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:0]],@"cipher with 2 different IV should be different");
    
	XCTAssertFalse([[BBAES encryptedDataFromData:data IV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0] isEqualToData:
				   [BBAES encryptedDataFromData:data IV:[BBAES IVFromString:@"iv2"] key:hashedKey options:0]], @"cipher with 2 different IV (strings) should be different");
	
	XCTAssertTrue([[BBAES encryptedDataFromData:data IV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0] isEqualToData:
				  [BBAES encryptedDataFromData:data IV:[BBAES IVFromString:@"iv1"] key:hashedKey options:0]], @"cipher with the same IV should be equal");
}

- (void)testEncryptionKeySize {
	NSString *password = @"Benoît";
	NSData *data = [@"secret message" dataUsingEncoding:NSUTF8StringEncoding];
	NSData *salt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	
	NSData *hashedKey, *encrypt, *decrypt;
	
	// 128 bits
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	encrypt = [BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:BBAESEncryptionOptionsIncludeIV];
	decrypt = [BBAES decryptedDataFromData:encrypt IV:nil key:hashedKey];
	XCTAssertTrue([data isEqualToData:decrypt], @"the input and decrypted data must be equal");
    
	// 192 bits
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize192 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	encrypt = [BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:BBAESEncryptionOptionsIncludeIV];
	decrypt = [BBAES decryptedDataFromData:encrypt IV:nil key:hashedKey];
	XCTAssertTrue([data isEqualToData:decrypt], @"the input and decrypted data must be equal");
	
	// 256 bits
	hashedKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	encrypt = [BBAES encryptedDataFromData:data IV:[BBAES randomIV] key:hashedKey options:BBAESEncryptionOptionsIncludeIV];
	decrypt = [BBAES decryptedDataFromData:encrypt IV:nil key:hashedKey];
	XCTAssertTrue([data isEqualToData:decrypt], @"the input and decrypted data must be equal");
	
}
@end
