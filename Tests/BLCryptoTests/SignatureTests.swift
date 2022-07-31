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
    
    func test_initWithBase64String() throws {
        let data = Utils.randomData(count: 128)
        _ = try Signature(base64Encoded: data.base64EncodedString())
    }
    
    func test_initWithData() throws {
        let data = Utils.randomData(count: 128)
        _ = Signature(data: data)
    }
}
