//
//  AES256Tests.swift
//  
//
//  Created by Marcelo Sarquis on 24.03.22.
//

import XCTest
@testable import BLCrypto

final class AES256Tests: XCTestCase {
    
    func testCBC_encryptDecrypt__shouldDoFullLoop() throws {
        // given
        let secret = UUID().uuidString
        let secretData = secret.data(using: .utf8)!
        
        // when
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: secretData), blockType: .cbc)
        let decrypted = try AES256.decrypt(encrypted, with: key, blockType: .cbc)
        let decryptedString = String(data: decrypted.data, encoding: .utf8)
        
        // then
        XCTAssertEqual(decryptedString, secret)
    }
    
    func testSimpleMath() throws {
        XCTAssertEqual(1, 2)
    }
    
//    func testCBC_encryptWithCryptoSwiftDecryptWithKrypt__shouldDoFullLoop() throws {
//        // given
//        let secret = UUID().uuidString
//        let secretData = secret.data(using: .utf8)!
//        let key = Data(count: 32) // 256 bit
//        let iv = Data(count: 16) // 128 bit
//
//        // when
//        let cryptoSwiftAES = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .pkcs7)
//        let encrypted = try cryptoSwiftAES.encrypt(secretData.bytes)
//        let decrypted = try AES256.decrypt(EncryptedMessage(data: Data(encrypted)), with: SymmetricKey(authenticationKey: key, initializationVector: iv), blockType: .cbc)
//        let decryptedString = String(data: decrypted.data, encoding: .utf8)
//
//        //then
//        XCTAssertEqual(decryptedString, secret)
//    }
    
//    func testCBC_encryptWithKryptDecryptWithCryptoSwift__shouldDoFullLoop() throws {
//        // given
//        let secret = UUID().uuidString
//        let secretData = secret.data(using: .utf8)!
//
//        // when
//        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: secretData), blockType: .cbc)
//        let cryptoSwiftAES = try AES(key: key.authenticationKey.bytes, blockMode: CBC(iv: key.initializationVector.bytes), padding: .pkcs7)
//        let decrypted = try cryptoSwiftAES.decrypt(encrypted.data.bytes)
//        let decryptedString = String(data: Data(decrypted), encoding: .utf8)
//
//        // then
//        XCTAssertEqual(decryptedString, secret)
//    }
    
    func testGCM_encryptDecrypt__shouldDoFullLoop() throws {
        // given
        let secret = UUID().uuidString
        let secretData = secret.data(using: .utf8)!

        // when
        let (encrypted, key) = try AES256.encrypt(ClearMessage(data: secretData), blockType: .gcm)
        let decrypted = try AES256.decrypt(encrypted, with: key, blockType: .gcm)
        let decryptedString = String(data: decrypted.data, encoding: .utf8)

        // then
        XCTAssertEqual(decryptedString, secret)
    }
}
