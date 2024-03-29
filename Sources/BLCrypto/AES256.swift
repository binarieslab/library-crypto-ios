//
//  AES256.swift
//  
//
//  Created by Marcelo Sarquis on 23.03.22.
//

import CommonCrypto
import Foundation

/// Symetric encryption used in Binaries Lab.
///
/// Only 256 bits (32 bytes) long keys are supported along with
/// CBC being the only supported block modes
public struct AES256 {
    
    /// Supported block types
    ///
    /// - cbc: legacy block mode only used for mainly for decreption
    public enum BlockType {
        case cbc
    }
    
    /// Encrypts a clear message with a symmetric key and returns an encrypted message.
    /// If the symmetric key is not provided, this functions generates a secure random data of correct length
    ///
    /// - Parameters:
    ///   - clearMessage: clear message object to encrypt
    ///   - symmetricKey: optional symmetric key
    ///   - blockType: which `BlockType` to use
    /// - Returns: Encrypted message and the symmetric key used for encryption
    /// - Throws: BLCryptoError
    public static func encrypt(_ clearMessage: ClearMessage, with key: SymmetricKey? = nil, blockType: BlockType) throws -> (encrypted: EncryptedMessage, key: SymmetricKey) {
        
        let key = key ?? SymmetricKey(
            authenticationKey: Utils.randomData(count: kCCKeySizeAES256),
            initializationVector: Utils.randomData(count: kCCKeySizeAES128)
        )
        
        let encrypted: Data
        
        switch blockType {
        case .cbc:
            encrypted = try cryptCBCPKCS7(data: clearMessage.data, key: key.authenticationKey, iv: key.initializationVector, operation: CCOperation(kCCEncrypt))
        }
        
        let encryptedMessage = EncryptedMessage(data: encrypted)
        return (encryptedMessage, key)
    }
    
    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - encryptedMessage: Encrypted message to decrypt
    ///   - symmetricKey: symmetric key
    ///   - blockType: which `BlockType` to use
    /// - Returns: Clear message
    /// - Throws: BLCryptoError
    public static func decrypt(_ encryptedMessage: EncryptedMessage, with key: SymmetricKey, blockType: BlockType) throws -> ClearMessage {
        
        let decryptedData: Data
        
        switch blockType {
        case .cbc:
            decryptedData = try cryptCBCPKCS7(data: encryptedMessage.data, key: key.authenticationKey, iv: key.initializationVector, operation: CCOperation(kCCDecrypt))
        }
        
        return ClearMessage(data: decryptedData)
    }
    
    /// Single function for encryption with CBC block mode
    ///
    /// - Parameters:
    ///   - data: data to encrypt/decrypt
    ///   - key: authentication key
    ///   - iv: initialization vector
    ///   - operation: kCCEncrypt/kCCDecrypt
    /// - Returns: tuple of encrypted data, authentication key and initialization vector
    /// - Throws: any errors returned by CommonCrypto
    static func cryptCBCPKCS7(data: Data, key: Data, iv: Data, operation: CCOperation) throws -> Data {
        
        let algorithm = CCAlgorithm(kCCAlgorithmAES)
        let options = CCOptions(kCCOptionPKCS7Padding)
        
        var dataOut = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var dataOutMoved = 0
        var status: CCCryptorStatus = CCCryptorStatus(kCCUnspecifiedError)
        
        key.withUnsafeBytes { ptr in
            
            guard let keyBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            
            iv.withUnsafeBytes { ptr in
                
                guard let ivBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return
                }
                
                data.withUnsafeBytes { ptr in
                    
                    guard let dataInBytes = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return
                    }
                    
                    status = CCCrypt(
                        operation,
                        algorithm,
                        options,
                        keyBytes,
                        key.count,
                        ivBytes,
                        dataInBytes,
                        data.count,
                        &dataOut,
                        dataOut.count,
                        &dataOutMoved
                    )
                }
            }
        }
        
        guard status == kCCSuccess else {
            throw BLCryptoError.cryptCBCPKCS7ccError(status: status)
        }
        
        let digest = Data(bytes: dataOut, count: dataOutMoved)
        return digest
    }
}
