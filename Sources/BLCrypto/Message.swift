//
//  Message.swift
//  
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import Foundation

public protocol Message {
    var data: Data { get }
    var base64String: String { get }
    init(data: Data)
    init(base64Encoded base64String: String) throws
}

public extension Message {
    
    /// Base64-encoded string of the message data
    var base64String: String {
        return data.base64EncodedString()
    }
    
    /// Creates an encrypted message with a base64-encoded string.
    ///
    /// - Parameter base64String: Base64-encoded data of the encrypted message
    /// - Throws: BLCryptoError
    init(base64Encoded base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw BLCryptoError.invalidBase64String
        }
        self.init(data: data)
    }
}
