//
//  EncryptedMessage.swift
//  
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import Foundation

public class EncryptedMessage: Message {
    
    /// Data of the message
    public let data: Data
    
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
    }
    
    /// Decrypts an encrypted message with a private key and returns a clear message.
    ///
    /// - Parameters:
    ///   - key: Private key to decrypt the mssage with
    ///   - padding: Padding to use during the decryption
    /// - Returns: Clear message
    /// - Throws: RSAError
    public func decrypted(with key: PrivateKey, paddingType: RSA.PaddingType) throws -> ClearMessage {
        
        guard SecKeyIsAlgorithmSupported(key.reference, .decrypt, paddingType.keyAlgorithm) else {
            throw RSAError.decryptionAlgorithmNotSupported
        }
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        
        var encryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&encryptedDataAsArray, length: data.count)
        
        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
            
            let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
            let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
            
            let dataToDecrypt = NSData(bytes: chunkData, length: chunkData.count)
            
            var error: Unmanaged<CFError>?
            
            let createdDecryptedData = SecKeyCreateDecryptedData(key.reference, paddingType.keyAlgorithm, dataToDecrypt, &error)
            
            guard let decryptedDataBuffer = createdDecryptedData as NSData? else {
                throw RSAError.chunkDecryptFailed(index: idx)
            }
            
            decryptedDataBytes += decryptedDataBuffer
            
            idx += blockSize
        }
        
        let decryptedData = Data(bytes: decryptedDataBytes, count: decryptedDataBytes.count)
        return ClearMessage(data: decryptedData)
    }
}
