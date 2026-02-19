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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientInstanceData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PLATFORM_DISCRIMINATOR
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.platformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_ACCESS_TOKEN_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.generatePKIData
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toRefreshToken
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldContainOnlyOnce
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.common.util.Base64Url
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.util.JWKSUtils
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER
import org.keycloak.util.TokenUtil.TOKEN_TYPE_DPOP

typealias ErrorHandler = (KeycloakError) -> Unit

fun KeycloakWebClient.testExchangeToken(
  subjectToken: String,
  clientId: String = ZETA_CLIENT,
  clientAssertion: String?,
  requestedClientScope: String? = null,
  useDPoP: Boolean = true,
  audience: String? = null,
  expectedError: ErrorHandler? = null,
): AccessTokenResponse {
  val keys = generatePKIData()
  val dPoPToken = if (useDPoP) smcbTokenGenerator.generateDPoPToken(keys, endpointURL = uriBuilder().tokenUrl(), accessToken = subjectToken) else null

  val either =
    tokenExchange(
      clientId = clientId,
      subjectToken = subjectToken,
      requestedClientScope = requestedClientScope,
      clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
      clientAssertion = clientAssertion,
      dPoPToken = dPoPToken,
      audience = audience,
    )

  if (expectedError != null) {
    either.isLeft() shouldBe true
    either.onLeft { expectedError(it) }

    return AccessTokenResponse()
  } else {
    val newAccessTokenResponse = either.shouldBeRight().reponseObject
    val newAccessToken = newAccessTokenResponse.token.toAccessToken()
    val newRefreshToken = newAccessTokenResponse.refreshToken.toRefreshToken()

    checkJSON(newAccessTokenResponse)

    if (useDPoP) {
      newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_DPOP
      val thumbprint = JWKSUtils.computeThumbprint(keys.jwk)
      newAccessToken.confirmation.keyThumbprint shouldBe thumbprint
    } else {
      newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER
    }

    newAccessToken.issuer shouldContain ZETA_REALM
    newAccessToken.issuedFor shouldBe clientId

    newAccessToken.subject shouldBe TELEMATIK_ID
    @Suppress("UNCHECKED_CAST") // https://ey-fp-dev.atlassian.net/browse/ZETAP-774
    val clientDataMap = newAccessToken.otherClaims[CLAIM_ACCESS_TOKEN_CLIENT_DATA].shouldNotBeNull() as Map<String, Any>

    val (_, clientId1, _, _, _, _, platformProductId) = clientDataMap.toObject<ClientInstanceData>()

    clientId1 shouldBe clientId
    platformProductId.productPlatform shouldBe Platform.LINUX

    if (requestedClientScope == CLIENT_B_SCOPE) {
      newAccessToken.audience shouldContain CLIENT_C_ID
    }

    newRefreshToken.subject shouldBe TELEMATIK_ID

    return newAccessTokenResponse
  }
}

private fun checkJSON(newAccessTokenResponse: AccessTokenResponse) {
  val tokenString = newAccessTokenResponse.token
  val split = tokenString.split(".").also { it.size shouldBe 3 }
  val body = split[1]
  val json = Base64Url.decode(body).toString(Charsets.UTF_8)

  json shouldContainOnlyOnce "\"$PROPERTY_PLATFORM_DISCRIMINATOR\":\"${platformProductId.productPlatform.value}\""
}
