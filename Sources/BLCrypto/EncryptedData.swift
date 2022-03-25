//
//  EncryptedData.swift
//  
//
//  Created by Marcelo Sarquis on 23.03.22.
//

import Foundation

public class EncryptedData: CryptData {
    
    /// Data of the message
    public let data: Data
    
    /// base64 encoded
    public var cipherKey: String?
    
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    public required init(data: Data) {
        self.data = data
    }
    
    /// Creates an encrypted message with data.
    ///
    /// - Parameter data: Data of the encrypted message.
    /// - Parameter cipherKey: Base64-encoded data of the cipher key.
    public convenience init(data: Data, cipherKey: String?) {
        self.init(data: data)
        self.cipherKey = cipherKey
    }
}
