//
//  BLCrypto.swift
//
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import SwiftUI

public struct BLCrypto {
    
    /// All encryption versions that are currently supported in Binaries Lab
    ///
    /// - gcmOAEP: AES 256 GCM symetric | RSA OAEP SHA256 asymetric
    /// - cbcPKCS1: AES 256 CBC symetric | RSA PKCS7 asymetric
    public enum VersionType {
        case gcmOAEP
        case cbcPKCS1
        
        /// returns AES block mode depending on Vivy encryption version
        var aes256BlockMode: AES256.BlockType {
            switch self {
            case .gcmOAEP:
                return .gcm
            case .cbcPKCS1:
                return .cbc
            }
        }
        
        /// returns RSA padding depending on Vivy encryption version
        var rsaPaddingType: RSA.PaddingType {
            switch self {
            case .gcmOAEP:
                return .oaep
            case .cbcPKCS1:
                return .pkcs1
            }
        }
    }

    /// Encrypts a clear data with a public key and returns an encrypted data.
    ///
    /// - Parameters:
    ///   - clearData: ClearData you want to encrypt
    ///   - key: Public key to encrypt the clear message with
    ///   - versionType: Version you want to use during the encryption
    /// - Returns: Encrypted data
    /// - Throws: BLCryptoError
    public static func encrypt(_ clearData: ClearData, with key: PublicKey, versionType version: VersionType) throws -> EncryptedData {
        
        // 1. Encrypt content with AES
        let clearMessage = ClearMessage(data: clearData.data)
        let (aesEncryptedMessage, aesSymmetricKey) = try AES256.encrypt(clearMessage, blockType: version.aes256BlockMode)
        
        // 2. Create cipher auth from the AES key and IV
        let cipherAttr = CipherAttr(key: aesSymmetricKey.authenticationKey, iv: aesSymmetricKey.initializationVector)
        let cipherAttrJSONData = try JSONEncoder().encode(cipherAttr)
        
        // 3. Encrypt meta message with RSA
        let cipherAttrClearMessage = ClearMessage(data: cipherAttrJSONData)
        
        let encryptedCipher = try RSA.encrypt(cipherAttrClearMessage, with: key, paddingType: version.rsaPaddingType)
        let encryptedCipherAttrBase64 = encryptedCipher.base64String
        
        return EncryptedData(data: aesEncryptedMessage.data, cipherKey: encryptedCipherAttrBase64)
    }
    
    /// Decrypts an encrypted data with a private key and returns a clear data.
    ///
    /// - Parameters:
    ///   - encryptedData: EncryptedData you want to decrypt
    ///   - key: Private key to decrypt the mssage with
    ///   - versionType: Version you want to use during the encryption
    /// - Returns: Clear data
    /// - Throws: BLCryptoError
    public static func decrypt(_ encryptedData: EncryptedData, with key: PrivateKey, versionType version: VersionType) throws -> ClearData {
        
        guard let cipherKey = encryptedData.cipherKey else {
            throw BLCryptoError.decryptionAlgorithmNotSupported // TODO
        }
        
        // 1. Decrypt cipher auth
        guard let encryptedCipherAuth = Data(base64Encoded: cipherKey) else {
            throw BLCryptoError.decryptionAlgorithmNotSupported // TODO
        }
        
        let encryptedCipherMessage = EncryptedMessage(data: encryptedCipherAuth)
        
        let cipherAttrMessage = try RSA.decrypt(encryptedCipherMessage, with: key, paddingType: version.rsaPaddingType)
        
        // 2. Decode cipher auth with the AES key in IV
        guard let cipherAttr = try? JSONDecoder().decode(CipherAttr.self, from: cipherAttrMessage.data) else {
            throw BLCryptoError.asn1ParsingFailed // TODO
        }
        
        // 3. Decrypt content with AES
        let encryptedMessage = EncryptedMessage(data: encryptedData.data)
        let symmetricKey = SymmetricKey(authenticationKey: cipherAttr.key, initializationVector: cipherAttr.iv)
        let clearMessage = try AES256.decrypt(encryptedMessage, with: symmetricKey, blockType: version.aes256BlockMode)
        
        return ClearData(data: clearMessage.data)
    }
}

/// DTO for AES256 authentication
struct CipherAttr: Codable {
    
    /// Authentication key
    let key: Data
    
    /// Initialization vector
    let iv: Data
    
    enum CodingKeys: String, CodingKey {
        case key = "base64EncodedKey"
        case iv = "base64EncodedIV"
    }
}
