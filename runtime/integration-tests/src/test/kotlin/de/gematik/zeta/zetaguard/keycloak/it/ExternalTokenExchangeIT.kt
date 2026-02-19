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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID2
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.common.util.SecretGenerator
import org.keycloak.events.Errors.INVALID_TOKEN

@Order(1)
class ExternalTokenExchangeIT : ZetaGuardFunSpec() {
  val keycloakWebClient = KeycloakWebClient()
  val baseUri = keycloakWebClient.uriBuilder().build().toString()
  val realmUrl = keycloakWebClient.uriBuilder().realmUrl().toString()

  init {
    test("External token exchange with SMC-B token, client assertion and DPoP header") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      // The zeta-client client knows about the JWT public key without client registration, because the key certificate is configured
      // hard coded in the "jwt.credential.certificate" attribute (See zeta-client.json)
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt)
    }

    test("Fail, if token is reused") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Token reuse detected"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Telematik ID mismatch") {
      val nonce2 = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jwt2 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce2)
      val smcbToken2 =
        smcbTokenGenerator.generateSMCBToken(
          subject = TELEMATIK_ID2,
          nonceString = nonce2,
          audiences = listOf(baseUri),
          certificateChain = listOf(leafCertificate),
        )

      keycloakWebClient.testExchangeToken(smcbToken2, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt2) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "Invalid subject"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("External token exchange fails without DPoP token") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jws = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jws, useDPoP = false) {
        it.error shouldBe INVALID_REQUEST
        it.errorDescription shouldBe "DPoP proof is missing"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Missing client_assertion") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = null) {
        it.error shouldBe INVALID_CLIENT
        // AbstractJWTClientValidator#validateClientAssertionParameters
        it.errorDescription shouldBe "Parameter client_assertion_type is missing"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("External token exchange fails with invalid audience") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jws = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)
      val smcbToken =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = listOf(ZETA_CLIENT), certificateChain = listOf(leafCertificate))

      keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = jws, requestedClientScope = CLIENT_B_SCOPE) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldBe "Expected audience not available in the token"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("SMC-B token fails without valid nonce") {
      val smcbToken = smcbTokenGenerator.generateSMCBToken(audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
      val jws = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), SecretGenerator.getInstance().randomBytes(16).toBase64())

      keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldBe "Invalid nonce value"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Nonce is not reusable") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val smcbToken = createSMCBToken(nonce)
      val jws1 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)
      val jws2 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce)

      keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = jws1, requestedClientScope = CLIENT_B_SCOPE)
      keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = jws2) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldBe "Invalid nonce value"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }
  }

  private fun createSMCBToken(nonce: String): String =
    smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
}
