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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import com.fasterxml.jackson.annotation.JsonProperty
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PRODUCT_VERSION
import org.keycloak.OAuth2Constants.GRANT_TYPE

data class OpaInput(val input: Input) {
  data class Input(
      @get:JsonProperty("authorization_request") val authorizationRequest: OpaAuthorizationRequest? = null,
      @get:JsonProperty("user_info") val userInfo: OpaUserInfo? = null,
      @get:JsonProperty("client_assertion") val clientAssertion: OpaClientAssertion? = null,
  )

  data class OpaAuthorizationRequest(
      val scopes: List<String>? = null,
      val audience: List<String>? = null,
      @get:JsonProperty(GRANT_TYPE) val grantType: String? = null,
      @get:JsonProperty("ip_address") val ipAddress: String? = null,
  )

  data class OpaUserInfo(@get:JsonProperty("professionOID") val professionOID: String? = null)

  data class OpaClientAssertion(val posture: OpaPosture? = null)

  data class OpaPosture(
      @get:JsonProperty(PROPERTY_PRODUCT_ID) val productId: String? = null,
      @get:JsonProperty(PROPERTY_PRODUCT_VERSION) val productVersion: String? = null,
  )
}
