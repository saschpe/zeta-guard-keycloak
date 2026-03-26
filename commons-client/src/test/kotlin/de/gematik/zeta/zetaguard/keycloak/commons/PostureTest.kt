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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.subjectKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import io.kotest.matchers.shouldBe
import org.keycloak.common.util.SecretGenerator

class PostureTest : ZetaGuardFunSpec() {
  init {
    val nonce = SecretGenerator.getInstance().randomBytes(16).toBase64()
    test("Software posture serialization") {
      val statement = clientStatementData(ZETA_CLIENT, nonce, PKIData(subjectKeyPair))
      val json = statement.posture.toJSON()
      val posture = json.toObject<SoftwarePosture>()

      posture shouldBe statement.posture
    }

    test("TPM posture serialization") {
      val statement = clientStatementData(ZETA_CLIENT, nonce, PKIData(subjectKeyPair), postureType = PostureType.TPM)
      val json = statement.posture.toJSON()
      val posture = json.toObject<TPMPosture>()

      posture shouldBe statement.posture
    }

    test("Statement serialization") {
      val statement1 = clientStatementData(ZETA_CLIENT, nonce, PKIData(subjectKeyPair))
      val json = statement1.toJSON()
      val statement2 = json.toObject<ClientStatementData>()

      statement2 shouldBe statement1
    }
  }
}
