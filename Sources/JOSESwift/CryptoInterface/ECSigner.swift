//
//  ECSigner.swift
//  JOSESwift
//
//  Created by Jarrod Moldrich on 02.07.18.
//
//  ---------------------------------------------------------------------------
//  Copyright 2019 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation
import CryptoKit

/// A `Signer` to sign an input with an elliptic curve algorithm.
internal struct ECSigner: SignerProtocol {
    typealias KeyType = EC.KeyType

    let algorithm: SignatureAlgorithm
    let privateKey: KeyType

    func sign(_ signingInput: Data) throws -> Data {
        return try EC.sign(signingInput, with: privateKey, and: algorithm)
    }
}

@available(iOS 13.0, *)
internal struct P256Signer: SignerProtocol {
  typealias KeyType = P256.Signing.PrivateKey

  let algorithm: SignatureAlgorithm = .ES256
  let privateKey: KeyType

  func sign(_ signingInput: Data) throws -> Data {
    return try privateKey.sign(signingInput)
  }
}

@available(iOS 13.0, *)
internal struct P384Signer: SignerProtocol {
  typealias KeyType = P384.Signing.PrivateKey

  let algorithm: SignatureAlgorithm = .ES384
  let privateKey: KeyType

  func sign(_ signingInput: Data) throws -> Data {
    return try privateKey.sign(signingInput)
  }
}

@available(iOS 13.0, *)
internal struct P521Signer: SignerProtocol {
  typealias KeyType = P521.Signing.PrivateKey

  let algorithm: SignatureAlgorithm = .ES512
  let privateKey: KeyType

  func sign(_ signingInput: Data) throws -> Data {
    return try privateKey.sign(signingInput)
  }
}

@available(iOS 13.0, *)
internal struct SecureEnclaveP256Signer: SignerProtocol {
  typealias KeyType = SecureEnclave.P256.Signing.PrivateKey

  let algorithm: SignatureAlgorithm = .ES256
  let privateKey: KeyType

  func sign(_ signingInput: Data) throws -> Data {
    return try privateKey.sign(signingInput)
  }
}
