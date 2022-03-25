//
//  SymmetricKey.swift
//  
//
//  Created by Marcelo Sarquis on 24.03.22.
//

import Foundation

public class SymmetricKey {
    
    /// Authentication key
    public let authenticationKey: Data
    
    /// Initialization vector
    public let initializationVector: Data
    
    /// Creates a symmetric key with a authentication key reference and initialization vector.
    ///
    /// - Parameter authenticationKey: Authentication key data of the symmetric
    /// - Parameter initializationVector: Initialization vector data of the symmetric
    public required init(authenticationKey: Data, initializationVector: Data) {
        self.authenticationKey = authenticationKey
        self.initializationVector = initializationVector
    }
}
