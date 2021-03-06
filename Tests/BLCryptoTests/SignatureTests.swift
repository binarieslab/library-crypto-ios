//
//  SignatureTests.swift
//  
//
//  Created by Marcelo Sarquis on 22.03.22.
//

import XCTest
@testable import BLCrypto

class SignatureTests: XCTestCase {
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private")
    
    func test_allDigestTypes() throws {
        
        let digestTypes: [Signature.DigestType] = [.sha1, .sha224, .sha256, .sha384, .sha512]
        
        for digestType in digestTypes {
            let data = Utils.randomData(count: 8192)
            let message = ClearMessage(data: data)
            let signature = try RSA.sign(message, with: privateKey, digestType: digestType)
            let isSuccessful = try RSA.verify(message, with: publicKey, signature: signature, digestType: digestType)
            XCTAssertTrue(isSuccessful)
        }
    }
    
    func test_base64String() throws {
        let data = Utils.randomData(count: 8192)
        let message = ClearMessage(data: data)
        let signature = try RSA.sign(message, with: privateKey, digestType: .sha1)
        XCTAssertEqual(signature.base64String, signature.data.base64EncodedString())
    }
    
    func test_initWithBase64String() throws {
        let data = Utils.randomData(count: 128)
        _ = try Signature(base64Encoded: data.base64EncodedString())
    }
    
    func test_initWithData() throws {
        let data = Utils.randomData(count: 128)
        _ = Signature(data: data)
    }
}
