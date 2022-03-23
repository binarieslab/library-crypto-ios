//
//  ClearMessage.swift
//  
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import Foundation
import CryptoSwift
import Security

public class ClearMessage: Message {
    
    /// Data of the message
    public let data: Data
    
    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }
    
    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - encoding: Encoding to use to generate the clear data
    /// - Throws: RSAError
    public convenience init(string: String, using encoding: String.Encoding) throws {
        guard let data = string.data(using: encoding) else {
            throw RSAError.stringToDataConversionFailed
        }
        self.init(data: data)
    }
    
    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: RSAError
    public func string(encoding: String.Encoding) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw RSAError.dataToStringConversionFailed
        }
        return str
    }
    
    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - padding: Padding to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: RSAError
    public func encrypted(with key: PublicKey, paddingType: RSA.PaddingType) throws -> EncryptedMessage {
        
        guard SecKeyIsAlgorithmSupported(key.reference, .encrypt, paddingType.keyAlgorithm) else {
            throw RSAError.encryptionAlgorithmNotSupported
        }
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        
        var maxChunkSize: Int
        switch paddingType {
        case .pkcs1:
            maxChunkSize = blockSize - 2 - 40
        case .oaep:
            maxChunkSize = blockSize - 2 - 64
        }
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            let dataToEncrypt = NSData(bytes: chunkData, length: chunkData.count)
            
            var error: Unmanaged<CFError>?
            
            let createdEncryptedData = SecKeyCreateEncryptedData(key.reference, paddingType.keyAlgorithm, dataToEncrypt as CFData, &error)
            
            guard let encryptedDataBuffer = createdEncryptedData as NSData? else {
                throw RSAError.chunkEncryptFailed(index: idx)
            }
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        let encryptedData = Data(bytes: encryptedDataBytes, count: encryptedDataBytes.count)
        return EncryptedMessage(data: encryptedData)
    }
    
    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: RSAError
    public func signed(with key: PrivateKey, digestType: Signature.DigestType) throws -> Signature {
        
        let digest = self.digest(digestType: digestType)
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = blockSize - 11
        
        guard digest.count <= maxChunkSize else {
            throw RSAError.invalidDigestSize(digestSize: digest.count, maxChunkSize: maxChunkSize)
        }
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        let dataToSign = NSData(bytes: digestBytes, length: digest.count)
        
        var error: Unmanaged<CFError>?
        
        let createdSignature = SecKeyCreateSignature(key.reference, digestType.keyAlgorithm, dataToSign, &error)
        
        guard let createdSignature = createdSignature, error == nil else {
            throw RSAError.signatureCreateFailed(status: error?.takeRetainedValue())
        }
        
        let signatureData = createdSignature as Data
        return Signature(data: signatureData)
    }
    
    /// Verifies the signature of a clear message.
    ///
    /// - Parameters:
    ///   - key: Public key to verify the signature with
    ///   - signature: Signature to verify
    ///   - digestType: Digest type used for the signature
    /// - Returns: Result of the verification
    /// - Throws: RSAError
    public func verify(with key: PublicKey, signature: Signature, digestType: Signature.DigestType) throws -> Bool {
        
        let digest = self.digest(digestType: digestType)
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        let signedData = NSData(bytes: digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.data.count)
        (signature.data as NSData).getBytes(&signatureBytes, length: signature.data.count)
        let signatureData = NSData(bytes: signatureBytes, length: signature.data.count)
        
        var error: Unmanaged<CFError>?
        
        let isSignatureIntact = SecKeyVerifySignature(key.reference, digestType.keyAlgorithm, signedData, signatureData, &error)
        
        if let error = error {
            throw RSAError.signatureVerifyFailed(status: error.takeRetainedValue())
        }
        
        return isSignatureIntact
    }
    
    func digest(digestType: Signature.DigestType) -> Data {
        
        let digest: Data
        switch digestType {
        case .sha1:
            digest = data.sha1()
        case .sha224:
            digest = data.sha224()
        case .sha256:
            digest = data.sha256()
        case .sha384:
            digest = data.sha384()
        case .sha512:
            digest = data.sha512()
        }
        return digest
    }
}
