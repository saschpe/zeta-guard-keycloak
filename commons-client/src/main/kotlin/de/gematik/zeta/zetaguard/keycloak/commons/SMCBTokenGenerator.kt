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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientInstanceData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.LinuxProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator.buildCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_SELF_ASSESSMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import jakarta.ws.rs.HttpMethod
import java.net.URI
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.UUID
import org.keycloak.OAuth2Constants
import org.keycloak.OAuth2Constants.DPOP_DEFAULT_ALGORITHM
import org.keycloak.OAuth2Constants.DPOP_JWT_HEADER_TYPE
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time.currentTime
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.representations.IDToken
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.util.DPoPGenerator
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

// DN bottom-up order as specified by https://www.rfc-editor.org/rfc/rfc1779#section-2.2
const val DN_GEMATIK = "CN=GEM.SMC-B,OU=Institution des Gesundheitswesens-CA der Telematikinfrastruktur,O=gematik GmbH,C=DE"
const val DN_PRAXIS = "CN=Praxis Dr. Eisenbart,STREET=Goethestr. 5,L=Essen,ST=Nordrhein-Westfalen,C=DE"

class SMCBTokenGenerator(issuerKeypair: KeyPair = generateKeyPair(), val subjectKeyPair: KeyPair = generateKeyPair()) {
  val keys = PKIData(subjectKeyPair)
  val certificate =
    buildCertificate(subjectName = DN_PRAXIS, subjectKeyPair = subjectKeyPair, issuerName = DN_GEMATIK, issuerKeyPair = issuerKeypair, isCA = false)

  fun generateClientAssertion(client: OIDCClientRepresentation, nonceString: String): String {
    val registrationAccessToken = client.registrationAccessToken.toAccessToken()
    val clientId = client.clientId
    val audiences = registrationAccessToken.audience.toList()

    return generateClientAssertion(clientId, audiences, nonceString)
  }

  fun generateClientAssertion(
    clientId: String,
    audiences: List<String>,
    nonceString: String,
    otherClaims: Map<String, Any> = createOtherClaims(clientId, nonceString, keys)
  ): String = generateSMCBToken(issuer = clientId, subject = clientId, audiences = audiences, certificateChain = listOf(), otherClaims = otherClaims)

  /**
   * Generate DPoP, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1
   *
   * Inspired by [DPoPGenerator.generateRsaSignedDPoPProof]
   */
  fun generateDPoPToken(keys: PKIData, httpMethod: String = HttpMethod.POST, endpointURL: URI, accessToken: String): String {
    val jwsRsaHeader = JWSHeader(DPOP_DEFAULT_ALGORITHM, DPOP_JWT_HEADER_TYPE, keys.jwk.keyId, keys.jwk)

    return DPoPGenerator()
      .generateSignedDPoPProof(
        SecretGenerator.getInstance().generateSecureID(),
        httpMethod,
        endpointURL.toString(),
        currentTime().toLong(),
        jwsRsaHeader,
        keys.keypair.private,
        accessToken,
      )
  }

  /**
   * Generate SMC-B-like token including x5c certificate header.
   *
   * According to https://github.com/gematik/zeta/blob/main/src/schemas/smb-id-token-jwt.yaml
   */
  fun generateSMCBToken(
    issuer: String = ZETA_CLIENT,
    subject: String = TELEMATIK_ID,
    nonceString: String = "noncence",
    issuedFor: String = CLIENT_C_ID, // target client
    audiences: List<String> = listOf(ZETA_CLIENT),
    certificateChain: List<X509Certificate> = listOf(certificate),
    otherClaims: Map<String, Any> = createOtherClaims(issuer, nonceString, keys),
  ): String {
    val signer = subjectKeyPair.createSignerContext()

    return JWSBuilder()
      .type(OAuth2Constants.JWT)
      .x5c(certificateChain)
      .jsonContent(
        IDToken().apply {
          id(UUID.randomUUID().toString())
          type(TOKEN_TYPE_BEARER)
          issuer(issuer)
          issuedFor(issuedFor)
          subject(subject)
          audience(*audiences.toTypedArray())
          expirationDate(Duration.ofDays(10))
          issuedNow()
          otherClaims.forEach { setOtherClaims(it.key, it.value) }
          nonce = nonceString
        })
      .sign(signer)
  }
}

val platformProductId = LinuxProductId("packaging", "app-id")

// Implement https://ey-fp-dev.atlassian.net/browse/ZETAP-774
fun clientInstanceData(clientId: String, mail: String = "info@acme.de") =
  ClientInstanceData("name", clientId, "acme-id", "Acme Inc.", mail, timeStampSeconds(), platformProductId)

// Implement https://ey-fp-dev.atlassian.net/browse/ZETAP-794
fun clientStatementData(clientId: String, nonceString: String, pkidata: PKIData, productId: ProductId = platformProductId, timeStampSeconds: Long = timeStampSeconds()): ClientStatementData {
  val nonceBytes = nonceString.fromBase64()
  val attestationChallenge = AttestationUtil.calculateAttestationChallenge(
      pkidata.jwkThumbPrint,
      nonceBytes
  )
  val softwarePosture =
    SoftwarePosture(productId, "demo_client", "0.2.0", "Linux", "6.12.54-linuxkit", "aarch64", pkidata.publicKeyPEM, attestationChallenge)

  return ClientStatementData(clientId, Platform.LINUX, PostureType.SOFTWARE, softwarePosture, timeStampSeconds)
}

private fun timeStampSeconds(): Long = System.currentTimeMillis() / 1000

fun createOtherClaims(clientId: String, nonceString: String, pkidata: PKIData) =
  mapOf(CLAIM_CLIENT_SELF_ASSESSMENT to clientInstanceData(clientId), CLAIM_CLIENT_STATEMENT to clientStatementData(clientId, nonceString, pkidata))
