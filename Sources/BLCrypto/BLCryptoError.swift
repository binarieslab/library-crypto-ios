//
//  BLCryptoError.swift
//  
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import Foundation
import CommonCrypto

public enum BLCryptoError: Error {
    
    case aesGCMEncryptionFailed
    case aesGCMDecryptionFailed
    case pemDoesNotContainKey
    case keyRepresentationFailed(error: CFError?)
    case keyGenerationFailed(error: CFError?)
    case keyCreateFailed(error: CFError?)
    case keyAddFailed(status: OSStatus)
    case keyCopyFailed(status: OSStatus)
    case tagEncodingFailed
    case asn1ParsingFailed
    case invalidAsn1RootNode
    case invalidAsn1Structure
    case invalidBase64String
    case rsaChunkDecryptFailed(index: Int)
    case rsaChunkEncryptFailed(index: Int)
    case encryptionAlgorithmNotSupported
    case decryptionAlgorithmNotSupported
    case stringToDataConversionFailed
    case dataToStringConversionFailed
    case invalidDigestSize(digestSize: Int, maxChunkSize: Int)
    case signatureCreateFailed(status: CFError?)
    case signatureVerifyFailed(status: CFError?)
    case pemFileNotFound(name: String)
    case derFileNotFound(name: String)
    case notAPublicKey
    case notAPrivateKey
    case x509CertificateFailed
    case cryptCBCPKCS7ccError(status: CCCryptorStatus)
    
    var localizedDescription: String {
        switch self {
        case .aesGCMEncryptionFailed:
            return "Couldn't encrypt AES for block type GCM."
        case .aesGCMDecryptionFailed:
            return "Couldn't decrypt AES for block type GCM."
        case .pemDoesNotContainKey:
            return "Couldn't get data from PEM key: no data available after stripping headers"
        case .keyRepresentationFailed(let error):
            return "Couldn't retrieve key data from the keychain: CFError \(String(describing: error))"
        case .keyGenerationFailed(let error):
            return "Couldn't generate key pair: CFError: \(String(describing: error))"
        case .keyCreateFailed(let error):
            return "Couldn't create key reference from key data: CFError \(String(describing: error))"
        case .keyAddFailed(let status):
            return "Couldn't retrieve key data from the keychain: OSStatus \(status)"
        case .keyCopyFailed(let status):
            return "Couldn't copy and retrieve key reference from the keychain: OSStatus \(status)"
        case .tagEncodingFailed:
            return "Couldn't create tag data for key"
        case .asn1ParsingFailed:
            return "Couldn't parse the ASN1 key data. Please file a bug at https://goo.gl/y67MW6"
        case .invalidAsn1RootNode:
            return "Couldn't parse the provided key because its root ASN1 node is not a sequence. The key is probably corrupt"
        case .invalidAsn1Structure:
            return "Couldn't parse the provided key because it has an unexpected ASN1 structure"
        case .invalidBase64String:
            return "The provided string is not a valid Base 64 string"
        case .rsaChunkDecryptFailed(let index):
            return "Couldn't decrypt chunk at index \(index)"
        case .rsaChunkEncryptFailed(let index):
            return "Couldn't encrypt chunk at index \(index)"
        case .encryptionAlgorithmNotSupported:
            return "The algorithm is not supported for the given key"
        case .decryptionAlgorithmNotSupported:
            return "The algorithm is not supported for the given key"
        case .stringToDataConversionFailed:
            return "Couldn't convert string to data using specified encoding"
        case .dataToStringConversionFailed:
            return "Couldn't convert data to string representation"
        case .invalidDigestSize(let digestSize, let maxChunkSize):
            return "Provided digest type produces a size (\(digestSize)) that is bigger than the maximum chunk size \(maxChunkSize) of the RSA key"
        case .signatureCreateFailed(let error):
            return "Couldn't sign provided data: CFError \(String(describing: error))"
        case .signatureVerifyFailed(let error):
            return "Couldn't verify signature of the provided data: CFError \(String(describing: error))"
        case .pemFileNotFound(let name):
            return "Couldn't find a PEM file named '\(name)'"
        case .derFileNotFound(let name):
            return "Couldn't find a DER file named '\(name)'"
        case .notAPublicKey:
            return "Provided key is not a valid RSA public key"
        case .notAPrivateKey:
            return "Provided key is not a valid RSA pivate key"
        case .x509CertificateFailed:
            return "Couldn't prepend the provided key because it has an unexpected structure"
        case .cryptCBCPKCS7ccError(let status):
            return "Couldn't complete the crpt operation with status '\(status)'"
        }
    }
}
