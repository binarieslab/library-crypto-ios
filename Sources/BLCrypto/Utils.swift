//
//  Utils.swift
//  
//
//  Created by Marcelo Sarquis on 24.03.22.
//

import Foundation

struct Utils {
    
    /// Generates random data of provided length
    ///
    /// - Parameter count: length of data
    /// - Returns: random data
    static func randomData(count: Int) -> Data {
        var randomBytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &randomBytes)
        guard status == errSecSuccess else {
            fatalError(#function)
        }
        return Data(randomBytes)
    }
}
