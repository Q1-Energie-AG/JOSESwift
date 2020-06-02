//
//  ECSigner.swift
//  JOSESwift
//

import CryptoKit
import Foundation

/// A `Signer` to sign an input with an elliptic curve algorithm.
internal struct P256Signer: SignerProtocol {
    typealias KeyType = P256.Signing.PrivateKey

    let algorithm: SignatureAlgorithm
    let privateKey: KeyType

    func sign(_ signingInput: Data) throws -> Data {
      return try P256EC.sign(signingInput, with: privateKey, and: algorithm)
    }
}
