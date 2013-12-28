//
//  main.m
//  BBAES Mac Example
//
//  Created by Benoît on 31/12/12.
//  Copyright (c) 2012 Pragmatic Code. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <BBAES/BBAES.h>
#import <CommonCrypto/CommonKeyDerivation.h>

void example();
void passwordBasedEncryptionExample();
void checkRepeatabilityWithPHPExample();

NSData * MD5HashFromString (NSString *string) {
	NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
	unsigned char hash[CC_MD5_DIGEST_LENGTH];
	(void) CC_MD5( [data bytes], (CC_LONG)[data length], hash );
	return [NSData dataWithBytes: hash length: CC_MD5_DIGEST_LENGTH];
}

int main(int argc, const char * argv[]) {
	@autoreleasepool {
		example();
		passwordBasedEncryptionExample();
		checkRepeatabilityWithPHPExample();
	}
    return 0;
}

void example() {
	NSData* salt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	NSData *key = [BBAES keyBySaltingPassword:@"password" salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	
	NSString *secretMessage = @"My secret message.";
	NSLog(@"Original message: %@", secretMessage);
	
	NSString *encryptedString = [secretMessage bb_AESEncryptedStringForIV:[BBAES randomIV] key:key options:BBAESEncryptionOptionsIncludeIV];
	NSLog(@"Encrypted message: %@", encryptedString);
	
	NSString *decryptedMessage = [encryptedString bb_AESDecryptedStringForIV:nil key:key];
	NSLog(@"Decrypted message: %@", decryptedMessage);
}


void passwordBasedEncryptionExample() {
	NSLog(@"\n\n--password Based Encryption Example--\n\n");
	
	NSString *password = @"password";
	
	// STEP 1: save an encrypted "content encryption key" from the user's password
	// 1: Generate a "key encryption key"
	NSData *salt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	NSData *keyEncryptionKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	
	// 2: Generate a "content encryption key"
	NSData *contentEncryptionKey = [BBAES randomDataWithLength:BBAESKeySize128];
	
	// 3: Encrypt the "content encryption key" with the "key encryption key".
	NSData *encryptedContentEncryptionKey = [BBAES encryptedDataFromData:contentEncryptionKey IV:[BBAES randomIV] key:keyEncryptionKey options:BBAESEncryptionOptionsIncludeIV];
	
	// 4: The encrypted "content encryption key" and the salt are saved in cleartext. (The password is given by the user and is not saved).
	
	// 5: Encrypt the content data
	NSString *message = @"my secret";
	NSLog(@"original message: %@",message);
	NSString *encryptedMessage = [message bb_AESEncryptedStringForIV:[BBAES randomIV] key:contentEncryptionKey options:BBAESEncryptionOptionsIncludeIV];
	
	// 6: Save the encrypted message.
	
	
	
	// STEP 2: Decrypting the content data using the "content encryption key" retrieved from the password + salt
	
	// 1. Retrieve the "content encryption key"
	NSData *rebuildKeyEncryptionKey = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	NSData *rebuildContentEncryptionKey = [BBAES decryptedDataFromData:encryptedContentEncryptionKey IV:nil key:rebuildKeyEncryptionKey];
	
	// 2: Decrypting the content data
	NSString *decryptedMessage = [encryptedMessage bb_AESDecryptedStringForIV:nil key:rebuildContentEncryptionKey];
	NSLog(@"Message after decryption is: %@",decryptedMessage);
	
	
	
	// STEP 3: The user changes his password.
	NSString *newPassword = @"newpassword";
	NSString *oldPassword = @"password";
	
	// 1. Check the old password
	NSData *currentKeyEncryptionKey = [BBAES keyBySaltingPassword:oldPassword salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	BOOL isOldPasswordIdentical = ([currentKeyEncryptionKey isEqualToData:
		 [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount]]);
	NSLog(@"is old password OK: %@",(isOldPasswordIdentical) ? @"YES" : @"NO");
	
	// 2. Retrieve the "content encryption key" with the old password and re-encrypting it with the new password
	NSData *currentContentEncryptionKey = [BBAES decryptedDataFromData:encryptedContentEncryptionKey IV:nil key:currentKeyEncryptionKey];
	
	NSData *newSalt = [BBAES randomDataWithLength:BBAESSaltDefaultLength];
	NSData *newKeyEncryptionKey = [BBAES keyBySaltingPassword:newPassword salt:newSalt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];

	NSData *newEncryptedContentEncryptionKey = [BBAES encryptedDataFromData:currentContentEncryptionKey IV:[BBAES randomIV] key:newKeyEncryptionKey options:BBAESEncryptionOptionsIncludeIV];
	
	// 3: The new encrypted "content encryption key" and the salt are saved.
	
	
	
	// STEP 4: Decrypting the content data with the new password
	
	// 1. Retrieve the "content encryption key"
	rebuildKeyEncryptionKey = [BBAES keyBySaltingPassword:newPassword salt:newSalt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	rebuildContentEncryptionKey = [BBAES decryptedDataFromData:newEncryptedContentEncryptionKey IV:nil key:rebuildKeyEncryptionKey];
	
	// 2: Decrypting the content data
	decryptedMessage = [encryptedMessage bb_AESDecryptedStringForIV:nil key:rebuildContentEncryptionKey];
	NSLog(@"Message after changing the password is: %@",decryptedMessage);
	
}


void checkRepeatabilityWithPHPExample() {
	// Same example is made in my AES php library to check the repeatability.
	
	NSLog(@"\n\n--Repeatability With PHP Example--\n\n");
	
	NSString *password = @"Passwôrd";
	NSString *message = @"Messâge";
	NSData *salt = MD5HashFromString(@"Sält");
	NSData *iv = [BBAES IVFromString:@"îv"];	
	
	NSLog(@"128 bits hashed key: %@", [BBAES stringFromData:[BBAES keyByHashingPassword:password keySize:BBAESKeySize128] encoding:BBAESDataEncodingHex]);
	NSLog(@"256 bits hashed key: %@", [BBAES stringFromData:[BBAES keyByHashingPassword:password keySize:BBAESKeySize256] encoding:BBAESDataEncodingHex]);
	
	NSLog(@"\n");
	
	NSLog(@"128 bits salted key: %@", [BBAES stringFromData:[BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount] encoding:BBAESDataEncodingHex]);
	
	NSLog(@"192 bits salted key: %@", [BBAES stringFromData:[BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize192 numberOfIterations:BBAESPBKDF2DefaultIterationsCount] encoding:BBAESDataEncodingHex]);
	
	NSLog(@"256 bits salted key: %@", [BBAES stringFromData:[BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount] encoding:BBAESDataEncodingHex]);
	
	NSLog(@"\n");
		
	NSData *key = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize128 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	NSString *encryptedString = [message bb_AESEncryptedStringForIV:iv key:key options:BBAESEncryptionOptionsIncludeIV];
	NSString *decryptedString = [encryptedString bb_AESDecryptedStringForIV:nil key:key];
	NSLog(@"128 bits: encryption: %@", encryptedString);
	NSLog(@"128 bits: decryption: %@", decryptedString);

	key = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize192 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	encryptedString = [message bb_AESEncryptedStringForIV:iv key:key options:BBAESEncryptionOptionsIncludeIV];
	decryptedString = [encryptedString bb_AESDecryptedStringForIV:nil key:key];
	NSLog(@"192 bits: encryption: %@", encryptedString);
	NSLog(@"192 bits: decryption: %@", decryptedString);
	
	key = [BBAES keyBySaltingPassword:password salt:salt keySize:BBAESKeySize256 numberOfIterations:BBAESPBKDF2DefaultIterationsCount];
	encryptedString = [message bb_AESEncryptedStringForIV:iv key:key options:BBAESEncryptionOptionsIncludeIV];
	decryptedString = [encryptedString bb_AESDecryptedStringForIV:nil key:key];
	NSLog(@"256 bits: encryption: %@", encryptedString);
	NSLog(@"256 bits: decryption: %@", decryptedString);
}

















