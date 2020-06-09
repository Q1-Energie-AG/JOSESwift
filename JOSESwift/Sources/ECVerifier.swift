//
//  ECVerifier.swift
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
#if canImport(CryptoKit)
import CryptoKit
#endif

/// A `Verifier` to verify a signature created with an elliptic curve algorithm.
internal struct ECVerifier: VerifierProtocol {
    typealias KeyType = EC.KeyType

    let algorithm: SignatureAlgorithm
    let publicKey: KeyType

    func verify(_ verifyingInput: Data, against signature: Data) throws -> Bool {
        return try EC.verify(verifyingInput, against: signature, with: publicKey, and: algorithm)
    }
}

@available(iOS 13.0, *)
internal struct P256Verifier: VerifierProtocol {
  typealias KeyType = P256.Signing.PublicKey

  let algorithm: SignatureAlgorithm = .ES256
  let publicKey: KeyType

  func verify(_ verifyingInput: Data, against signature: Data) throws -> Bool {
      return try publicKey.verify(verifyingInput, against: signature)
  }
}

@available(iOS 13.0, *)
internal struct P384Verifier: VerifierProtocol {
  typealias KeyType = P384.Signing.PublicKey

  let algorithm: SignatureAlgorithm = .ES384
  let publicKey: KeyType

  func verify(_ verifyingInput: Data, against signature: Data) throws -> Bool {
      return try publicKey.verify(verifyingInput, against: signature)
  }
}

@available(iOS 13.0, *)
internal struct P521Verifier: VerifierProtocol {
  typealias KeyType = P521.Signing.PublicKey

  let algorithm: SignatureAlgorithm = .ES512
  let publicKey: KeyType

  func verify(_ verifyingInput: Data, against signature: Data) throws -> Bool {
      return try publicKey.verify(verifyingInput, against: signature)
  }
}
