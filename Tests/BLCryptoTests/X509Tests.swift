//
//  X509Tests.swift
//  
//
//  Created by Marcelo Sarquis on 22.03.22.
//

import XCTest
@testable import BLCrypto

class X509CertificateTests: XCTestCase {
    
    let publicKey = try! TestUtils.publicKey(name: "swiftyrsa-public")
    let privateKey = try! TestUtils.privateKey(name: "swiftyrsa-private")
    
    /// Verify the ASN1 sruc with the ASN1 parser (private key)
    func testX509CertificateValidityPrivateKey() throws {
        guard let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        let privateKeyX509: Data = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        
        XCTAssertTrue(try privateKeyX509.hasX509Header())
    }
    
    /// Test the function in charge of verifying if a key is headerless or not
    func testHeaderlessKeyVerificationFunc() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        // Correct key
        XCTAssertTrue(try publicKeyData.isAnHeaderlessKey())
        XCTAssertTrue(try privateKeyData.isAnHeaderlessKey())
        
        // Example of incorrect key (here with a X509 header)
        let publicKeyX509 = try RSA.prependX509KeyHeader(keyData: publicKeyData)
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        XCTAssertFalse(try publicKeyX509.isAnHeaderlessKey())
        XCTAssertFalse(try privateKeyX509.isAnHeaderlessKey())
    }
    
    /// Verify that the header added corresponds to the X509 key
    func testX509HeaderVerificationPublicKey() throws {
        // Generated on https://www.devglan.com/online-tools/rsa-encryption-decryption which uses X.509 certificate for public key
        guard let path = TestUtils.bundle.path(forResource: "swiftyrsa-public-base64-X509-format", ofType: "txt") else {
            return XCTFail("file not found in bundle")
        }
        let str = try String(contentsOf: URL(fileURLWithPath: path), encoding: .utf8)
        if let publicKey = try? PublicKey(base64Encoded: str) { // Creating a public key strip the X509 header
            let publicKey509 = try RSA.prependX509KeyHeader(keyData: publicKey.data())
            let publicKey509Base64 = publicKey509.base64EncodedString()
            XCTAssertEqual(publicKey509Base64, str)
        } else {
            return XCTFail("Key isn't valid")
        }
    }
    
    /// Test if the key's format is correct with the hasX509Header func
    func testX509KeyHeader() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }

        let publicKeyX509 = try RSA.prependX509KeyHeader(keyData: publicKeyData)
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        
        XCTAssertTrue(try publicKeyX509.hasX509Header())
        XCTAssertTrue(try privateKeyX509.hasX509Header())
    }
    
    /// Verify if the X509 header can be stripped
    func testStripX509HeaderPrivateKey() throws {
        guard let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        
        let privateKeyStripped = try RSA.stripKeyHeader(keyData: privateKeyX509)
        XCTAssertEqual(privateKeyData, privateKeyStripped)
    }
    
    /// Test if a key with X509 header can encrypt and decrypt a given simple message
    func testEncryptionDecryptionSimple() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try RSA.prependX509KeyHeader(keyData: publicKeyData)
        
        let clear = "Hello world !"
        let clearMessage = try ClearMessage(string: clear, using: .utf8)
        
        let encrypted = try RSA.encrypt(clearMessage, with: PublicKey(data: publicKeyX509), paddingType: .pkcs1)
        let decrypted = try RSA.decrypt(encrypted, with: PrivateKey(data: privateKeyX509), paddingType: .pkcs1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), clear)
    }
    
    /// Test if a key with X509 header can encrypt and decrypt a given long message
    func testEncryptionDecryptionLong() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try RSA.prependX509KeyHeader(keyData: publicKeyData)
        
        let clear = [String](repeating: "a", count: 9999).joined(separator: "")
        let clearMessage = try ClearMessage(string: clear, using: .utf8)
        
        let encrypted = try RSA.encrypt(clearMessage, with: PublicKey(data: publicKeyX509), paddingType: .pkcs1)
        let decrypted = try RSA.decrypt(encrypted, with: PrivateKey(data: privateKeyX509), paddingType: .pkcs1)
        
        XCTAssertEqual(try? decrypted.string(encoding: .utf8), clear)
    }
    
    /// Test if a key with X509 header can encrypt and decrypt a given random message
    func testEncryptionDecryptionRandomBytes() throws {
        guard let publicKeyData = try? publicKey.data(), let privateKeyData = try? privateKey.data() else {
            return XCTFail("invalid data")
        }
        
        let privateKeyX509 = try RSA.prependX509KeyHeader(keyData: privateKeyData)
        let publicKeyX509 = try RSA.prependX509KeyHeader(keyData: publicKeyData)
        
        let data = Utils.randomData(count: 2048)
        let clearMessage = ClearMessage(data: data)
        
        let encrypted = try RSA.encrypt(clearMessage, with: PublicKey(data: publicKeyX509), paddingType: .pkcs1)
        let decrypted = try RSA.decrypt(encrypted, with: PrivateKey(data: privateKeyX509), paddingType: .pkcs1)
        
        XCTAssertEqual(decrypted.data, data)
    }
}
