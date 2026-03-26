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
package de.gematik.zeta.zetaguard.keycloak.client_assertion

import com.fasterxml.jackson.databind.exc.InvalidTypeIdException
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.asMap
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldContainOnlyOnce
import io.kotest.matchers.string.shouldNotContain
import kotlin.collections.get

class ClientInstanceDataTest : ZetaGuardFunSpec() {
  init {
    test("Serialize and deserialize polymorphic data") {
      val android = AndroidProductId("package", listOf("8214b94cd8c44024e7f65a8bbf221b51f617fa4818a30761c596aa5e34dc3359"))
      val apple = AppleProductId("macos", listOf("bundle"))
      val linux = LinuxProductId("packaging", "app-id")
      val windows = WindowsProductId("store", "family")
      val platforms = mapOf("android" to android, "apple" to apple, "linux" to linux, "windows" to windows)

      platforms.forEach { platform ->
        val data = ClientInstanceData("name", "client", "jens-id", "jens", "info@jens.de", 4711L, platform.value)
        val json = data.toJSON()

        json shouldContain "\"name\":\"name\""
        json shouldContain "\"owner_mail\":\"info@jens.de\""
        json shouldContainOnlyOnce "\"$PROPERTY_PLATFORM_DISCRIMINATOR\":\"${platform.key}\""
        json shouldNotContain "@type"

        val clientInstanceData = json.toObject<ClientInstanceData>()
        clientInstanceData shouldBe data
      }
    }

    test("Conversion from/to map") {
      val android = AndroidProductId("package", listOf("fingerprint"))
      val data = ClientInstanceData("name", "client", "jens-id", "jens", "info@jens.de", 4711L, android)
      val asMap = data.asMap()

      asMap shouldContain ("owner_mail" to "info@jens.de")
      asMap shouldContain ("platform_product_id" to android.asMap())

      val platform = asMap["platform_product_id"] as Map<*, *>
      platform["@type"] shouldBe null
      platform[PROPERTY_PLATFORM_DISCRIMINATOR] shouldBe "android"

      asMap.toObject<ClientInstanceData>() shouldBe data
    }

    test("Broken platform") {
      val json =
          """
          {
            "name": "name",
            "client_id": "client",
            "manufacturer_id": "jens-id",
            "manufacturer_name": "jens",
            "owner_mail": "info@jens.de",
            "registration_timestamp": 4711,
            "platform_product_id": {
              "$PROPERTY_PLATFORM_DISCRIMINATOR": "jens"
            }
          }
          """
              .trimIndent()

      shouldThrow<InvalidTypeIdException> { json.toObject<ClientInstanceData>() }
    }
  }
}
