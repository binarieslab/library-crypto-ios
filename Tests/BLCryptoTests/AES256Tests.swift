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
}
