//
//  ClearData.swift
//  
//
//  Created by Marcelo Sarquis on 23.03.22.
//

import Foundation

public class ClearData: CryptData {
    
    /// Data of the message
    public let data: Data
    
    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }
}
