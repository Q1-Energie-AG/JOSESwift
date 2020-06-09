//
//  ECSigner.swift
//  JOSESwift
//

import CryptoKit
import Foundation

extension P256.Signing.PrivateKey: SignerProtocol {
  var algorithm: SignatureAlgorithm {
    return .ES256
  }

  func sign(_ signingInput: Data) throws -> Data {
    let sig = try signature(for: signingInput)

    let ecSignatureTLV = [UInt8](sig.derRepresentation)
    do {
      let ecSignature = try ecSignatureTLV.read(.sequence)
      let varlenR = try Data(ecSignature.read(.integer))
      let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
      let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: ECCurveType.P256.coordinateOctetLength)
      let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: ECCurveType.P256.coordinateOctetLength)

      return fixlenR + fixlenS
    } catch {
      throw ECError.signingFailed(description: "Could not unpack ASN.1 EC signature.")
    }
  }
}

extension P384.Signing.PrivateKey: SignerProtocol {
  var algorithm: SignatureAlgorithm { .ES384 }

  func sign(_ signingInput: Data) throws -> Data {
    let sig = try signature(for: signingInput)

    let ecSignatureTLV = [UInt8](sig.derRepresentation)
    do {
      let ecSignature = try ecSignatureTLV.read(.sequence)
      let varlenR = try Data(ecSignature.read(.integer))
      let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
      let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: ECCurveType.P384.coordinateOctetLength)
      let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: ECCurveType.P384.coordinateOctetLength)

      return fixlenR + fixlenS
    } catch {
      throw ECError.signingFailed(description: "Could not unpack ASN.1 EC signature.")
    }
  }
}

extension P521.Signing.PrivateKey: SignerProtocol {
  var algorithm: SignatureAlgorithm { .ES512 }

  func sign(_ signingInput: Data) throws -> Data {
    let sig = try signature(for: signingInput)

    let ecSignatureTLV = [UInt8](sig.derRepresentation)
    do {
      let ecSignature = try ecSignatureTLV.read(.sequence)
      let varlenR = try Data(ecSignature.read(.integer))
      let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
      let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: ECCurveType.P521.coordinateOctetLength)
      let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: ECCurveType.P521.coordinateOctetLength)

      return fixlenR + fixlenS
    } catch {
      throw ECError.signingFailed(description: "Could not unpack ASN.1 EC signature.")
    }
  }
}

extension SecureEnclave.P256.Signing.PrivateKey: SignerProtocol {
  var algorithm: SignatureAlgorithm { .ES256 }

  func sign(_ signingInput: Data) throws -> Data {
    let sig = try signature(for: signingInput)

    let ecSignatureTLV = [UInt8](sig.derRepresentation)
    do {
      let ecSignature = try ecSignatureTLV.read(.sequence)
      let varlenR = try Data(ecSignature.read(.integer))
      let varlenS = try Data(ecSignature.skip(.integer).read(.integer))
      let fixlenR = Asn1IntegerConversion.toRaw(varlenR, of: ECCurveType.P256.coordinateOctetLength)
      let fixlenS = Asn1IntegerConversion.toRaw(varlenS, of: ECCurveType.P256.coordinateOctetLength)

      return fixlenR + fixlenS
    } catch {
      throw ECError.signingFailed(description: "Could not unpack ASN.1 EC signature.")
    }
  }
}

// Converting integers to and from DER encoded ASN.1 as described here:
// https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-integer
// This conversion is required because the Secure Enclave only supports generating ASN.1 encoded signatures,
// while the JWS Standard requires raw signatures, where the R and S are unsigned integers with a fixed length:
// https://github.com/airsidemobile/JOSESwift/pull/156#discussion_r292370209
// https://tools.ietf.org/html/rfc7515#appendix-A.3.1
internal struct Asn1IntegerConversion {
  static func toRaw(_ data: Data, of fixedLength: Int) -> Data {
    let varLength = data.count
    if varLength > fixedLength + 1 {
      fatalError("ASN.1 integer is \(varLength) bytes long when it should be < \(fixedLength + 1).")
    }
    if varLength == fixedLength + 1 {
      assert(data.first == 0)
      return data.dropFirst()
    }
    if varLength == fixedLength {
      return data
    }
    if varLength < fixedLength {
      // pad to fixed length using 0x00 bytes
      return Data(count: fixedLength - varLength) + data
    }
    fatalError("Unable to parse ASN.1 integer. This should be unreachable.")
  }

  static func fromRaw(_ data: Data) -> Data {
    assert(data.count > 0)
    let msb: UInt8 = 0b1000_0000
    // drop all leading zero bytes
    let varlen = data.drop { $0 == 0 }
    guard let firstNonZero = varlen.first else {
      // all bytes were zero so the encoded value is zero
      return Data(count: 1)
    }
    if (firstNonZero & msb) == msb {
      return Data(count: 1) + varlen
    }
    return varlen
  }
}
