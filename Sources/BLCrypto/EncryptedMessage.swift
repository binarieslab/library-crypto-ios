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
}
