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
