//
//  Signer.swift
//  JOSESwift
//
//  Created by Daniel Egger on 18/08/2017.
//  Modified by Jarrod Moldrich on 02.07.18.
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

protocol SignerProtocol {
  var algorithm: SignatureAlgorithm { get }

  /// Signs input data.
  ///
  /// - Parameter signingInput: The input to sign.
  /// - Returns: The signature.
  /// - Throws: `JWSError` if any error occurs while signing.
  func sign(_ signingInput: Data) throws -> Data
}

public struct Signer<KeyType> {
  let signer: SignerProtocol

  /// Constructs a signer used to sign a JWS.
  ///
  /// - Parameters:
  ///   - signingAlgorithm: A desired `SignatureAlgorithm`.
  ///   - privateKey: The private key used to sign the JWS. Currently supported key types are: `SecKey`.
  /// - Returns: A fully initialized `Signer` or `nil` if provided key is of the wrong type.
  public init?(signingAlgorithm: SignatureAlgorithm, privateKey: KeyType) {
    switch signingAlgorithm {
    case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
      guard type(of: privateKey) is RSASigner.KeyType.Type else {
        return nil
      }
      // swiftlint:disable:next force_cast
      self.signer = RSASigner(algorithm: signingAlgorithm, privateKey: privateKey as! RSASigner.KeyType)
    case .ES256, .ES384, .ES512:

      if #available(iOS 13.0, *) {
        switch type(of: privateKey) {
        case is P256Signer.KeyType.Type:
          self.signer = P256Signer(privateKey: privateKey as! P256Signer.KeyType)
          return
        case is P384Signer.KeyType.Type:
          self.signer = P384Signer(privateKey: privateKey as! P384Signer.KeyType)
          return
        case is P521Signer.KeyType.Type:
          self.signer = P521Signer(privateKey: privateKey as! P521Signer.KeyType)
          return
        case is SecureEnclaveP256Signer.KeyType.Type:
          self.signer = SecureEnclaveP256Signer(privateKey: privateKey as! SecureEnclaveP256Signer.KeyType)
          return
        default:
          break
        }
      }

      guard type(of: privateKey) is ECSigner.KeyType.Type else {
        return nil
      }
      // swiftlint:disable:next force_cast
      self.signer = ECSigner(algorithm: signingAlgorithm, privateKey: privateKey as! ECSigner.KeyType)
    }
  }

  internal func sign(header: JWSHeader, payload: Payload) throws -> Data {
    guard let alg = header.algorithm, alg == signer.algorithm else {
      throw JWSError.algorithmMismatch
    }

    guard let signingInput = [header, payload].asJOSESigningInput() else {
      throw JWSError.cannotComputeSigningInput
    }

    return try signer.sign(signingInput)
  }
}

extension Array where Element == DataConvertible {
  func asJOSESigningInput() -> Data? {
    let encoded = map { component in
      component.data().base64URLEncodedString()
    }

    return encoded.joined(separator: ".").data(using: .ascii)
  }
}
