//
//  BLCryptoTests.swift
//  
//
//  Created by Marcelo Sarquis on 24.03.22.
//

import XCTest
@testable import BLCrypto

final class BLCryptoTests: XCTestCase {
    
    let slogan = "In Computing, Binary refers to an executable, a type of binary file that contains machine code for the computer to execute. A Laboratory, or lab, is a place providing an opportunity for experimentation, observation, or practice in a field of study; in our case, software development."
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private")
    
    func testEncryptDecrypt__shouldDoWholeLoop() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        
        // when
        let encrypted = try BLCrypto.encrypt(ClearData(data: messageData), with: publicKey, versionType: .gcmOAEP)
        let decrypted = try BLCrypto.decrypt(encrypted, with: privateKey, versionType: .gcmOAEP)
        
        // then
        XCTAssertEqual(String(data: decrypted.data, encoding: .utf8), message)
    }
    
    func testEncrypt__shouldHaveProperlyBase64EncodedCipherAuth() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        
        // when
        let encrypted = try BLCrypto.encrypt(ClearData(data: messageData), with: publicKey, versionType: .gcmOAEP)
        let decryptedCipherKey = try RSA.decrypt(EncryptedMessage(data: Data(base64Encoded: encrypted.cipherKey!)!), with: privateKey, paddingType: .oaep)
        let cipherAttr = try JSONDecoder().decode(CipherAttr.self, from: decryptedCipherKey.data)
        
        // then
        XCTAssertEqual(cipherAttr.key.count, 32)
        XCTAssertEqual(cipherAttr.iv.count, 16)
    }
    
    func testDecrypt_gcmOAEP__shouldDecrypt() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: messageData), blockType: .gcm)
        let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key.authenticationKey, iv: key.initializationVector))
        let cipherKeyEncrypted = try RSA.encrypt(ClearMessage(data: cipherKeyData), with: publicKey, paddingType: .oaep)
        let encryptedData = EncryptedData(data: encrypted.data, cipherKey: cipherKeyEncrypted.base64String)
        
        // when
        let decrypted = try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .gcmOAEP)
        
        // then
        XCTAssertEqual(String(data: decrypted.data, encoding: .utf8)!, message)
    }
    
    func testDecrypt_cbcPKCS1__shouldDecrypt() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: messageData), blockType: .cbc)
        let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key.authenticationKey, iv: key.initializationVector))
        let cipherKeyEncrypted = try RSA.encrypt(ClearMessage(data: cipherKeyData), with: publicKey, paddingType: .pkcs1)
        let encryptedData = EncryptedData(data: encrypted.data, cipherKey: cipherKeyEncrypted.base64String)
        
        // when
        let decrypted = try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .cbcPKCS1)
        
        // then
        XCTAssertEqual(String(data: decrypted.data, encoding: .utf8)!, message)
    }
    
    func testDecrypt_gcmOAEP_cbc__shouldThrowPublicErrorForCorrectedGCMblockType() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: messageData), blockType: .cbc)
        let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key.authenticationKey, iv: key.initializationVector))
        let cipherKeyEncrypted = try RSA.encrypt(ClearMessage(data: cipherKeyData), with: publicKey, paddingType: .oaep)
        let encryptedData = EncryptedData(data: encrypted.data, cipherKey: cipherKeyEncrypted.base64String)
        
        // when
        XCTAssertThrowsError(try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .gcmOAEP)) { error in
            // then
            XCTAssertEqual(error as? BLCryptoError, BLCryptoError.aesGCMDecryptionFailed)
        }
    }
    
    func testDecrypt_gcmOAEP_pkcs1RSAPadding__shouldThrowPublicErrorForCorrectPaddingTypeOaep() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: messageData), blockType: .gcm)
        let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key.authenticationKey, iv: key.initializationVector))
        let cipherKeyEncrypted = try RSA.encrypt(ClearMessage(data: cipherKeyData), with: publicKey, paddingType: .pkcs1)
        let encryptedData = EncryptedData(data: encrypted.data, cipherKey: cipherKeyEncrypted.base64String)
        
        // when
        XCTAssertThrowsError(try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .gcmOAEP)) { error in
            // then
            XCTAssertEqual(error as? BLCryptoError, BLCryptoError.rsaChunkDecryptFailed(index: 0))
        }
    }
    
    func testDecrypt_gcmOAEP_cbcPKCS1Version__shouldThrowPublicErrorForCorrectVersionTypeGcmOAEP() throws {
        // given
        let message = UUID().uuidString
        let messageData = message.data(using: .utf8)!
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: messageData), blockType: .gcm)
        let cipherKeyData = try JSONEncoder().encode(CipherAttr(key: key.authenticationKey, iv: key.initializationVector))
        let cipherKeyEncrypted = try RSA.encrypt(ClearMessage(data: cipherKeyData), with: publicKey, paddingType: .oaep)
        let encryptedData = EncryptedData(data: encrypted.data, cipherKey: cipherKeyEncrypted.base64String)
        
        // when
        XCTAssertThrowsError(try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .cbcPKCS1)) { error in
            // then
            XCTAssertEqual(error as? BLCryptoError, BLCryptoError.rsaChunkDecryptFailed(index: 0))
        }
    }
    
    func testContract_decrypt_gcmOAEP__decryptedMessageShouldMatchSlogan() throws {
        // given
        let encryptedContractData = Data(base64Encoded: TestUtils.contentsOfFile(name: "ehr-gcm-contract-message-base64").stringTrimmingWhitespacesAndNewlines)!
        let contractCipherKey = TestUtils.contentsOfFile(name: "ehr-gcm-contract-cipher-key-base64").stringTrimmingWhitespacesAndNewlines
        let pemEncoded = TestUtils.contentsOfFile(name: "openssl-private-key-pkcs1-pem").stringTrimmingWhitespacesAndNewlines
        let privateKey = try PrivateKey(pemEncoded: pemEncoded)
        
        let encryptedData = EncryptedData(data: encryptedContractData, cipherKey: contractCipherKey)
        
        // when
        let decrypted = try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .gcmOAEP)
        
        // then
        XCTAssertEqual(String(data: decrypted.data, encoding: .utf8)!, slogan)
    }
    
    func testContract_decrypt_cbcPKCS1__decryptedMessageShouldMatchSlogan() throws {
        // given
        let encryptedContractData = Data(base64Encoded: TestUtils.contentsOfFile(name: "ehr-cbc-contract-message-base64").stringTrimmingWhitespacesAndNewlines)!
        let contractCipherKey = TestUtils.contentsOfFile(name: "ehr-cbc-contract-cipher-key-base64").stringTrimmingWhitespacesAndNewlines
        let pemEncoded = TestUtils.contentsOfFile(name: "openssl-private-key-pkcs1-pem").stringTrimmingWhitespacesAndNewlines
        let privateKey = try PrivateKey(pemEncoded: pemEncoded)
        let encryptedData = EncryptedData(data: encryptedContractData, cipherKey: contractCipherKey)
        
        // when
        let decrypted = try BLCrypto.decrypt(encryptedData, with: privateKey, versionType: .cbcPKCS1)
        
        // then
        XCTAssertEqual(String(data: decrypted.data, encoding: .utf8)!, slogan)
    }
}

private extension Data {
    var stringTrimmingWhitespacesAndNewlines: String {
        String(data: self, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
