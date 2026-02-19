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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleProductId
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.clientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.generatePKIData
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.string.shouldContain

@Order(1)
class ClientStatementDataIT : ZetaGuardFunSpec() {
  val keycloakWebClient = KeycloakWebClient()
  val baseUri = keycloakWebClient.uriBuilder().build().toString()
  val realmUrl = keycloakWebClient.uriBuilder().realmUrl().toString()

  init {
    test("Invalid combination") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, smcbTokenGenerator.keys).toMutableMap()
      val invalidStatement = clientStatementData(ZETA_CLIENT, nonce, smcbTokenGenerator.keys, AppleProductId("macos", listOf("bundle")))
      otherClaims[CLAIM_CLIENT_STATEMENT] = invalidStatement

      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce, otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain "Invalid combination"
      }
    }

    test("Invalid attestation challenge") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, generatePKIData())
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce, otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain "Attestation challenge does not match"
      }
    }

    test("Invalid attestation timestamp") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, smcbTokenGenerator.keys).toMutableMap()
      val invalidStatement = clientStatementData(ZETA_CLIENT, nonce, smcbTokenGenerator.keys, timeStampSeconds = 12)
      otherClaims[CLAIM_CLIENT_STATEMENT] = invalidStatement

      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), nonce, otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain "Invalid attestation timestamp"
      }
    }
  }

  private fun createSMCBToken(nonce: String): String =
    smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
}
