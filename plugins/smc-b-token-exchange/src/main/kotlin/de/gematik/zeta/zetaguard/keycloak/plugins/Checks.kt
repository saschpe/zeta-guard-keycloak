/*-
 * #%L
 * referencevalidator-cli
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
package de.gematik.zeta.zetaguard.keycloak.plugins

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toThumbprint
import de.gematik.zeta.zetaguard.keycloak.plugins.token.KeycloakValidationError
import de.gematik.zeta.zetaguard.keycloak.plugins.token.ZetaGuardTokenExchangeContext

internal fun checkSoftwarePosture(context: ZetaGuardTokenExchangeContext, posture: SoftwarePosture): Either<KeycloakValidationError, Unit> = either {
  val nonceBytes = context.token.nonce.fromBase64()
  val jwkThumbPrint = context.clientJWK.toThumbprint()
  val attestationChallenge = calculateAttestationChallenge(jwkThumbPrint, nonceBytes)

  ensure(attestationChallenge == posture.attestationChallenge) { invalidClientAttestation("Attestation challenge does not match") }
}

internal fun checkPostureType(clientStatementData: ClientStatementData): Either<KeycloakValidationError, Unit> = either {
  if (clientStatementData.postureType in listOf(PostureType.SOFTWARE, PostureType.TPM)) {
    val platform = clientStatementData.posture.platformProductId.productPlatform

    ensure(platform in listOf(Platform.WINDOWS, Platform.LINUX)) {
      invalidClientClaim("Invalid combination of »${clientStatementData.postureType}« and »${platform}«")
    }
  }
}
