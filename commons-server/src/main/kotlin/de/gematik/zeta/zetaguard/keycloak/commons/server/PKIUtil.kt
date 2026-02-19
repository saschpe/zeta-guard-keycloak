/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */
package de.gematik.zeta.zetaguard.keycloak.commons.server

import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAPublicKeySpec
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.crypto.AsymmetricSignatureSignerContext
import org.keycloak.crypto.AsymmetricSignatureVerifierContext
import org.keycloak.crypto.ECDSASignatureSignerContext
import org.keycloak.crypto.ECDSASignatureVerifierContext
import org.keycloak.crypto.SignatureSignerContext
import org.keycloak.crypto.SignatureVerifierContext
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKBuilder
import org.keycloak.util.JWKSUtils.computeThumbprint
import org.keycloak.util.JWKSUtils.getKeyWrapper

const val RSA_SIGNATURE_ALGORITHM = "SHA256WithRSA"
const val ECDSA_SIGNATURE_ALGORITHM = "SHA256WithECDSA"
const val EC_CURVE_P256 = "SECP256R1"

fun generateKeyPair(curveName: String = EC_CURVE_P256): KeyPair {
  try {
    val keyGen = CryptoIntegration.getProvider().getKeyPairGen("EC")
    val randomGen = SecureRandom.getInstance("SHA1PRNG")
    val ecSpec = ECGenParameterSpec(curveName)
    keyGen.initialize(ecSpec, randomGen)

    return keyGen.generateKeyPair()
  } catch (e: Exception) {
    throw RuntimeException(e)
  }
}

/**
 * Compute the raw RFC 7638 Thumbprint of a JWK
 *
 * @See [https://datatracker.ietf.org/doc/html/rfc7638]
 * @See [https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1]
 */
fun JWK.toThumbprint(): ByteArray = computeThumbprint(this).fromBase64()

data class PKIData(val keypair: KeyPair) {
  val jwk: JWK by lazy { keypair.toJWK() }
  val jwks: JSONWebKeySet by lazy { JSONWebKeySet().apply { keys = arrayOf(jwk) } }
  val jwkThumbPrint: ByteArray by lazy { jwk.toThumbprint() }
  val publicKeyPEM: String by lazy { keypair.public.toPEM() }
}

fun KeyPair.toJWK(): JWK = JWKBuilder.create().ec(public)

fun generatePKIData(): PKIData = PKIData(generateKeyPair())

/**
 * Derives the PublicKey from a given PrivateKey.
 *
 * @return The corresponding PublicKey.
 * @throws UnsupportedOperationException if the key type is not RSA or EC.
 */
fun PrivateKey.getPublicKey(): PublicKey {
  return when (this) {
    /**
     * --- RSA KEYS --- We must be able to cast to RSAPrivateCrtKey (CRT stands for Chinese Remainder Theorem). This interface provides access to the
     * modulus AND the public exponent, which are the two components of an RSA public key.
     */
    is RSAPrivateCrtKey -> {
      println("Key is RSA. Using modulus and public exponent.")
      val keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)
      val pubKeySpec = RSAPublicKeySpec(modulus, publicExponent)

      keyFactory.generatePublic(pubKeySpec)
    }

    /**
     * --- EC (Elliptic Curve) KEYS ---
     *
     * The public key is a point (W) on the curve. This point is calculated by multiplying the curve's generator (G) by the private key's scalar (S).
     *
     * W = G * S
     *
     * We need Bouncy Castle's internal math libraries to perform this elliptic curve point multiplication.
     */
    is ECPrivateKey -> {
      val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
      val point = parameters.g.multiply(d) // g is the generator point, part of the spec.
      val pubKeySpec = ECPublicKeySpec(point, parameters)

      keyFactory.generatePublic(pubKeySpec)
    }

    else -> throw UnsupportedOperationException("Unsupported private key type: $algorithm")
  }
}

fun PublicKey.createVerifierContext(): SignatureVerifierContext {
  val jwk = createJWK()
  val key = getKeyWrapper(jwk, true).apply { publicKey = this@createVerifierContext }

  return when (this) {
    is ECPublicKey -> ECDSASignatureVerifierContext(key)
    is RSAPublicKey -> AsymmetricSignatureVerifierContext(key)

    else -> throw unsupportedOperationException()
  }
}

fun KeyPair.createSignerContext(): SignatureSignerContext {
  val jwk = public.createJWK()
  val key =
    getKeyWrapper(jwk, true).apply {
      publicKey = public
      privateKey = private
    }

  return when (public) {
    is ECPublicKey -> ECDSASignatureSignerContext(key)
    is RSAPublicKey -> AsymmetricSignatureSignerContext(key)

    else -> throw unsupportedOperationException()
  }
}

fun PublicKey.createJWK(): JWK =
  when (this) {
    is ECPublicKey -> JWKBuilder.create().ec(this)
    is RSAPublicKey -> JWKBuilder.create().rs256(this)

    else -> throw unsupportedOperationException()
  }

fun KeyPair.signingAlgorithm() =
  when (public) {
    is ECPublicKey -> ECDSA_SIGNATURE_ALGORITHM
    is RSAPublicKey -> RSA_SIGNATURE_ALGORITHM

    else -> throw unsupportedOperationException()
  }

fun KeyPair.unsupportedOperationException() = public.unsupportedOperationException()

fun PublicKey.unsupportedOperationException(): UnsupportedOperationException =
  UnsupportedOperationException("Public key type $javaClass not supported.")
