//
//  RSA.swift
//  
//
//  Created by Marcelo Sarquis on 21.03.22.
//

import CryptoSwift
import Foundation
import Security

public typealias Padding = SecPadding
public typealias KeyAlgorithm = SecKeyAlgorithm

public enum RSA {
    
    public enum PaddingType {
        case pkcs1
        case oaep
        
        var keyAlgorithm: KeyAlgorithm {
            switch self {
            case .pkcs1: return .rsaEncryptionPKCS1
            case .oaep: return .rsaEncryptionOAEPSHA256
            }
        }
    }
    
    public enum SizeType: Int {
      case bit256 = 256
      case bit2048 = 2048
      case bit4096 = 4096
    }
    
    static func base64String(pemEncoded pemString: String) throws -> String {
        let lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix("-----BEGIN") && !line.hasPrefix("-----END")
        }
        
        guard lines.count != 0 else {
            throw BLCryptoError.pemDoesNotContainKey
        }
        
        return lines.joined(separator: "")
    }
    
    static func isValidKeyReference(_ reference: SecKey, forClass requiredClass: CFString) -> Bool {
        
        let attributes = SecKeyCopyAttributes(reference) as? [CFString: Any]
        guard let keyType = attributes?[kSecAttrKeyType] as? String, let keyClass = attributes?[kSecAttrKeyClass] as? String else {
            return false
        }
        
        let isRSA = keyType == (kSecAttrKeyTypeRSA as String)
        let isValidClass = keyClass == (requiredClass as String)
        return isRSA && isValidClass
    }
    
    static func format(keyData: Data, withPemType pemType: String) -> String {
        
        func split(_ str: String, byChunksOfLength length: Int) -> [String] {
            return stride(from: 0, to: str.count, by: length).map { index -> String in
                let startIndex = str.index(str.startIndex, offsetBy: index)
                let endIndex = str.index(startIndex, offsetBy: length, limitedBy: str.endIndex) ?? str.endIndex
                return String(str[startIndex..<endIndex])
            }
        }
        
        // Line length is typically 64 characters, except the last line.
        // See https://tools.ietf.org/html/rfc7468#page-6 (64base64char)
        // See https://tools.ietf.org/html/rfc7468#page-11 (example)
        let chunks = split(keyData.base64EncodedString(), byChunksOfLength: 64)
        
        let pem = [
            "-----BEGIN \(pemType)-----",
            chunks.joined(separator: "\n"),
            "-----END \(pemType)-----"
        ]
        
        return pem.joined(separator: "\n")
    }
    
    static func data(forKeyReference reference: SecKey) throws -> Data {
        
        var error: Unmanaged<CFError>?
        let data = SecKeyCopyExternalRepresentation(reference, &error)
        guard let unwrappedData = data as Data? else {
            throw BLCryptoError.keyRepresentationFailed(error: error?.takeRetainedValue())
        }
        return unwrappedData
    }
    
    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - clearMessage: ClearMessage you want to encrypt
    ///   - key: Public key to encrypt the clear message with
    ///   - padding: Padding to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: BLCryptoError
    public static func encrypt(_ clearMessage: ClearMessage, with key: PublicKey, paddingType: PaddingType) throws -> EncryptedMessage {
        
        guard SecKeyIsAlgorithmSupported(key.reference, .encrypt, paddingType.keyAlgorithm) else {
            throw BLCryptoError.encryptionAlgorithmNotSupported
        }
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        
        var maxChunkSize: Int
        switch paddingType {
        case .pkcs1:
            maxChunkSize = blockSize - 2 - 40
        case .oaep:
            maxChunkSize = blockSize - 2 - 64
        }
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: clearMessage.data.count)
        (clearMessage.data as NSData).getBytes(&decryptedDataAsArray, length: clearMessage.data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            let dataToEncrypt = NSData(bytes: chunkData, length: chunkData.count)
            
            var error: Unmanaged<CFError>?
            
            let createdEncryptedData = SecKeyCreateEncryptedData(key.reference, paddingType.keyAlgorithm, dataToEncrypt as CFData, &error)
            
            guard let encryptedDataBuffer = createdEncryptedData as NSData? else {
                throw BLCryptoError.chunkEncryptFailed(index: idx)
            }
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        let encryptedData = Data(bytes: encryptedDataBytes, count: encryptedDataBytes.count)
        return EncryptedMessage(data: encryptedData)
    }
    
    /// Decrypts an encrypted message with a private key and returns a clear message.
    ///
    /// - Parameters:
    ///   - encryptedMessage: EncryptedMessage you want to decrypt
    ///   - key: Private key to decrypt the mssage with
    ///   - padding: Padding to use during the decryption
    /// - Returns: Clear message
    /// - Throws: BLCryptoError
    public static func decrypt(_ encryptedMessage: EncryptedMessage, with key: PrivateKey, paddingType: RSA.PaddingType) throws -> ClearMessage {
        
        guard SecKeyIsAlgorithmSupported(key.reference, .decrypt, paddingType.keyAlgorithm) else {
            throw BLCryptoError.decryptionAlgorithmNotSupported
        }
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        
        var encryptedDataAsArray = [UInt8](repeating: 0, count: encryptedMessage.data.count)
        (encryptedMessage.data as NSData).getBytes(&encryptedDataAsArray, length: encryptedMessage.data.count)
        
        var decryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < encryptedDataAsArray.count {
            
            let idxEnd = min(idx + blockSize, encryptedDataAsArray.count)
            let chunkData = [UInt8](encryptedDataAsArray[idx..<idxEnd])
            
            let dataToDecrypt = NSData(bytes: chunkData, length: chunkData.count)
            
            var error: Unmanaged<CFError>?
            
            let createdDecryptedData = SecKeyCreateDecryptedData(key.reference, paddingType.keyAlgorithm, dataToDecrypt, &error)
            
            guard let decryptedDataBuffer = createdDecryptedData as NSData? else {
                throw BLCryptoError.chunkDecryptFailed(index: idx)
            }
            
            decryptedDataBytes += decryptedDataBuffer
            
            idx += blockSize
        }
        
        let decryptedData = Data(bytes: decryptedDataBytes, count: decryptedDataBytes.count)
        return ClearMessage(data: decryptedData)
    }
    
    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: BLCryptoError
    public static func sign(_ clearMessage: ClearMessage, with key: PrivateKey, digestType: Signature.DigestType) throws -> Signature {
        
        let digest = clearMessage.digest(digestType: digestType)
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = blockSize - 11
        
        guard digest.count <= maxChunkSize else {
            throw BLCryptoError.invalidDigestSize(digestSize: digest.count, maxChunkSize: maxChunkSize)
        }
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        let dataToSign = NSData(bytes: digestBytes, length: digest.count)
        
        var error: Unmanaged<CFError>?
        
        let createdSignature = SecKeyCreateSignature(key.reference, digestType.keyAlgorithm, dataToSign, &error)
        
        guard let createdSignature = createdSignature, error == nil else {
            throw BLCryptoError.signatureCreateFailed(status: error?.takeRetainedValue())
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
    /// - Throws: BLCryptoError
    public static func verify(_ clearMessage: ClearMessage, with key: PublicKey, signature: Signature, digestType: Signature.DigestType) throws -> Bool {
        
        let digest = clearMessage.digest(digestType: digestType)
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        let signedData = NSData(bytes: digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.data.count)
        (signature.data as NSData).getBytes(&signatureBytes, length: signature.data.count)
        let signatureData = NSData(bytes: signatureBytes, length: signature.data.count)
        
        var error: Unmanaged<CFError>?
        
        let isSignatureIntact = SecKeyVerifySignature(key.reference, digestType.keyAlgorithm, signedData, signatureData, &error)
        
        if let error = error {
            throw BLCryptoError.signatureVerifyFailed(status: error.takeRetainedValue())
        }
        
        return isSignatureIntact
    }
    
    /// Will generate a new private and public key
    ///
    /// - Parameters:
    ///   - size: Indicates the total number of bits in this cryptographic key
    /// - Returns: A touple of a private and public key
    /// - Throws: Throws and error if the tag cant be parsed or if keygeneration fails
    public static func generateRSAKeyPair(size sizeType: SizeType) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
        return try generateRSAKeyPair(size: sizeType, applyUnitTestWorkaround: false)
    }
    
    static func generateRSAKeyPair(size sizeType: SizeType, applyUnitTestWorkaround: Bool = false) throws -> (privateKey: PrivateKey, publicKey: PublicKey) {
      
        guard let tagData = UUID().uuidString.data(using: .utf8) else {
            throw BLCryptoError.stringToDataConversionFailed
        }
        
        // @hack Don't store permanently when running unit tests, otherwise we'll get a key creation error (NSOSStatusErrorDomain -50)
        // @see http://www.openradar.me/36809637
        // @see https://stackoverflow.com/q/48414685/646960
        let isPermanent = applyUnitTestWorkaround ? false : true
        
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: sizeType.rawValue,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: isPermanent,
                kSecAttrApplicationTag: tagData
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let pubKey = SecKeyCopyPublicKey(privKey) else {
            throw BLCryptoError.keyGenerationFailed(error: error?.takeRetainedValue())
        }
        let privateKey = try PrivateKey(reference: privKey)
        let publicKey = try PublicKey(reference: pubKey)
        
        return (privateKey: privateKey, publicKey: publicKey)
    }
    
    static func addKey(_ keyData: Data, isPublic: Bool) throws ->  SecKey {
        
        let keyClass = isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        
        let sizeInBits = keyData.count * 8
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits),
            kSecReturnPersistentRef: true
        ]
        
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, &error) else {
            throw BLCryptoError.keyCreateFailed(error: error?.takeRetainedValue())
        }
        return key
    }
    
    /**
     This method strips the x509 header from a provided ASN.1 DER key.
     If the key doesn't contain a header, the DER data is returned as is.
     
     Supported formats are:
     
     Headerless:
     SEQUENCE
         INTEGER (1024 or 2048 bit) -- modulo
         INTEGER -- public exponent
     
     With x509 header:
     SEQUENCE
         SEQUENCE
         OBJECT IDENTIFIER 1.2.840.113549.1.1.1
         NULL
         BIT STRING
         SEQUENCE
         INTEGER (1024 or 2048 bit) -- modulo
         INTEGER -- public exponent
     
     Example of headerless key:
     https://lapo.it/asn1js/#3082010A0282010100C1A0DFA367FBC2A5FD6ED5A071E02A4B0617E19C6B5AD11BB61192E78D212F10A7620084A3CED660894134D4E475BAD7786FA1D40878683FD1B7A1AD9C0542B7A666457A270159DAC40CE25B2EAE7CCD807D31AE725CA394F90FBB5C5BA500545B99C545A9FE08EFF00A5F23457633E1DB84ED5E908EF748A90F8DFCCAFF319CB0334705EA012AF15AA090D17A9330159C9AFC9275C610BB9B7C61317876DC7386C723885C100F774C19830F475AD1E9A9925F9CA9A69CE0181A214DF2EB75FD13E6A546B8C8ED699E33A8521242B7E42711066AEC22D25DD45D56F94D3170D6F2C25164D2DACED31C73963BA885ADCB706F40866B8266433ED5161DC50E4B3B0203010001
     
     Example of key with X509 header (notice the additional ASN.1 sequence):
     https://lapo.it/asn1js/#30819F300D06092A864886F70D010101050003818D0030818902818100D0674615A252ED3D75D2A3073A0A8A445F3188FD3BEB8BA8584F7299E391BDEC3427F287327414174997D147DD8CA62647427D73C9DA5504E0A3EED5274A1D50A1237D688486FADB8B82061675ABFA5E55B624095DB8790C6DBCAE83D6A8588C9A6635D7CF257ED1EDE18F04217D37908FD0CBB86B2C58D5F762E6207FF7B92D0203010001
     */
    static func stripKeyHeader(keyData: Data) throws -> Data {
        
        let node: Asn1Parser.Node
        do {
            node = try Asn1Parser.parse(data: keyData)
        } catch {
            throw BLCryptoError.asn1ParsingFailed
        }
        
        // Ensure the raw data is an ASN1 sequence
        guard case .sequence(let nodes) = node else {
            throw BLCryptoError.invalidAsn1RootNode
        }
        
        // Detect whether the sequence only has integers, in which case it's a headerless key
        let onlyHasIntegers = nodes.filter { node -> Bool in
            if case .integer = node {
                return false
            }
            return true
        }.isEmpty
        
        // Headerless key
        if onlyHasIntegers {
            return keyData
        }
        
        // If last element of the sequence is a bit string, return its data
        if let last = nodes.last, case .bitString(let data) = last {
            return data
        }
        
        // If last element of the sequence is an octet string, return its data
        if let last = nodes.last, case .octetString(let data) = last {
            return data
        }
        
        // Unable to extract bit/octet string or raw integer sequence
        throw BLCryptoError.invalidAsn1Structure
    }
    
    /**
        This method prepend the x509 header to the given PublicKey data.
        If the key already contain a x509 header, the given data is returned as is.
            It letterally does the opposite of the previous method :
            From a given headerless key :
                    SEQUENCE
                        INTEGER (1024 or 2048 bit) -- modulo
                        INTEGER -- public exponent
            the key is returned following the X509 header :
                    SEQUENCE
                        SEQUENCE
                        OBJECT IDENTIFIER 1.2.840.113549.1.1.1
                        NULL
                        BIT STRING
                        SEQUENCE
                        INTEGER (1024 or 2048 bit) -- modulo
                        INTEGER -- public exponent
     */
    
    static func prependX509KeyHeader(keyData: Data) throws -> Data {
        if try keyData.isAnHeaderlessKey() {
            let x509certificate: Data = keyData.prependx509Header()
            return x509certificate
        } else if try keyData.hasX509Header() {
            return keyData
        } else { // invalideHeader
            throw BLCryptoError.x509CertificateFailed
        }
    }
}

private extension ClearMessage {
    
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

#if !swift(>=4.1)
extension Array {
    func compactMap<ElementOfResult>(_ transform: (Element) throws -> ElementOfResult?) rethrows -> [ElementOfResult] {
        return try self.flatMap(transform)
    }
}
#endif

#if !swift(>=4.0)
extension NSTextCheckingResult {
    func range(at idx: Int) -> NSRange {
        return self.rangeAt(1)
    }
}
#endif
