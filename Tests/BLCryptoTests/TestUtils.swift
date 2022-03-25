//
//  TestUtils.swift
//  
//
//  Created by Marcelo Sarquis on 22.03.22.
//

import Foundation
import BLCrypto
import XCTest

struct TestError: Error {
    let description: String
}

public class TestUtils: NSObject {
    
    static let bundle = Bundle.module
    
    static public func pemKeyString(name: String) -> String {
        let pubPath = bundle.path(forResource: name, ofType: "pem")!
        return (try! NSString(contentsOfFile: pubPath, encoding: String.Encoding.utf8.rawValue)) as String
    }
    
    static public func contentsOfFile(name: String) -> Data {
        let pubPath  = bundle.path(forResource: name, ofType: nil)!
        return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
    }
    
    static public func derKeyData(name: String) -> Data {
        let pubPath  = bundle.path(forResource: name, ofType: "der")!
        return (try! Data(contentsOf: URL(fileURLWithPath: pubPath)))
    }
    
    static public func publicKey(name: String) throws -> PublicKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PublicKey(pemEncoded: pemString)
    }
    
    static public func privateKey(name: String) throws -> PrivateKey {
        guard let path = bundle.path(forResource: name, ofType: "pem") else {
            throw TestError(description: "Couldn't load key for provided path")
        }
        let pemString = try String(contentsOf: URL(fileURLWithPath: path))
        return try PrivateKey(pemEncoded: pemString)
    }
    
    static func assertThrows(type: BLCryptoError, file: StaticString = #file, line: UInt = #line, block: () throws ->  Void) {
        do {
            try block()
            XCTFail("The line above should fail", file: file, line: line)
        } catch {
            guard let swiftyBLCryptoError = error as? BLCryptoError else {
                return XCTFail("Error is not a SwiftyBLCryptoError", file: file, line: line)
            }
            XCTAssertEqual(swiftyBLCryptoError, type, file: file, line: line)
        }
    }
}

extension BLCryptoError: Equatable {
    public static func == (lhs: BLCryptoError, rhs: BLCryptoError) -> Bool {
        switch (lhs, rhs) {
        case
            (.aesGCMEncryptionFailed, .aesGCMEncryptionFailed),
            (.aesGCMDecryptionFailed, .aesGCMDecryptionFailed),
            (.pemDoesNotContainKey, .pemDoesNotContainKey),
            (.keyRepresentationFailed, .keyRepresentationFailed),
            (.keyGenerationFailed, .keyGenerationFailed),
            (.keyCreateFailed, .keyCreateFailed),
            (.keyAddFailed, .keyAddFailed),
            (.keyCopyFailed, .keyCopyFailed),
            (.tagEncodingFailed, .tagEncodingFailed),
            (.asn1ParsingFailed, .asn1ParsingFailed),
            (.invalidAsn1RootNode, .invalidAsn1RootNode),
            (.invalidAsn1Structure, .invalidAsn1Structure),
            (.invalidBase64String, .invalidBase64String),
            (.rsaChunkDecryptFailed, .rsaChunkDecryptFailed),
            (.rsaChunkEncryptFailed, .rsaChunkEncryptFailed),
            (.encryptionAlgorithmNotSupported, .encryptionAlgorithmNotSupported),
            (.decryptionAlgorithmNotSupported, .decryptionAlgorithmNotSupported),
            (.stringToDataConversionFailed, .stringToDataConversionFailed),
            (.dataToStringConversionFailed, .dataToStringConversionFailed),
            (.invalidDigestSize, .invalidDigestSize),
            (.signatureCreateFailed, .signatureCreateFailed),
            (.signatureVerifyFailed, .signatureVerifyFailed),
            (.pemFileNotFound, .pemFileNotFound),
            (.derFileNotFound, .derFileNotFound),
            (.notAPublicKey, .notAPublicKey),
            (.notAPrivateKey, .notAPrivateKey),
            (.x509CertificateFailed, .x509CertificateFailed),
            (.cryptCBCPKCS7ccError, .cryptCBCPKCS7ccError):
            return true
        default:
            return false
        }
    }
}
