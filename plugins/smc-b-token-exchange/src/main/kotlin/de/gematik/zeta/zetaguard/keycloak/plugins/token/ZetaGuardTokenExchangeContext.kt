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
package de.gematik.zeta.zetaguard.keycloak.plugins.token

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientInstanceData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.IDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.Success
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.time.Duration
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION
import org.keycloak.crypto.KeyStatus
import org.keycloak.crypto.KeyUse
import org.keycloak.crypto.KeyWrapper
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.representations.IDToken
import org.keycloak.representations.JsonWebToken

/**
 * Collect all relevant data during token exchange.
 *
 * This data will be used for subsequent checks and validations.
 */
class ZetaGuardTokenExchangeContext(val exchangeProvider: ZetaGuardTokenExchangeProvider) : Success {
  lateinit var clientJWK: JWK
  lateinit var token: IDToken
  lateinit var certificate: X509Certificate
  lateinit var telematikID: String
  lateinit var professionOID: String
  lateinit var subjectOrganisation: String
  lateinit var subjectName: String
  lateinit var clientInstanceData: ClientInstanceData
  lateinit var clientStatementData: ClientStatementData

  // TTLs provided by OPA decision (in seconds)
  lateinit var accessTokenTTLSeconds: Duration
  lateinit var refreshTokenTTLSeconds: Duration

  val context: TokenExchangeContext
    get() = exchangeProvider.context()

  val subjectToken: String = context.params.subjectToken ?: throw IllegalStateException("No subject token found")

  val clientAssertionToken: String = context.formParams.getFirst(CLIENT_ASSERTION) ?: throw IllegalStateException("No client assertion token found")
  val clientAssertion: JsonWebToken by lazy { clientAssertionToken.toJsonWebToken() }
  val certificatePublicKey: PublicKey by lazy { certificate.publicKey }

  private val tokenInfo: IDTokenInfo = subjectToken.toIDTokenInfo()

  val header: JWSHeader
    get() = tokenInfo.header

  fun createCertificateKeyWrapper() =
    KeyWrapper().apply {
      this.kid = header.keyId
      this.type = "EC"
      this.publicKey = certificatePublicKey
      this.status = KeyStatus.ACTIVE
      this.use = KeyUse.SIG
      this.algorithm = header.algorithm.name
    }

  /**
   * Note, that this will raise an exception if the values have not been initialized upon usage time.
   *
   * However, at this point of time previous checks should have prevented this case from happening anyway.
   */
  val data: ZetaGuardTokenExchangeData
    get() = ZetaGuardTokenExchangeData(telematikID, professionOID, subjectOrganisation, subjectName, accessTokenTTLSeconds, refreshTokenTTLSeconds)
}
