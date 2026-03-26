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

import com.fasterxml.jackson.annotation.JsonProperty
import java.beans.ConstructorProperties

const val PROPERTY_NAME = "name"
const val PROPERTY_CLIENT_ID = "client_id"
const val PROPERTY_MANUFACTURER_ID = "manufacturer_id"
const val PROPERTY_MANUFACTURER_NAME = "manufacturer_name"
const val PROPERTY_OWNER_MAIL = "owner_mail"
const val PROPERTY_REGISTRATION_TIMESTAMP = "registration_timestamp"
const val PROPERTY_PLATFORM_PRODUCT_ID = "platform_product_id"

/**
 * JSON classes for Client assertion
 *
 * The Client self assessment data is part of the Client Assertion JWT.
 * It contains information about the client instance.
 *
 * @see [https://github.com/gematik/zeta/blob/main/src/schemas/client-instance.yaml]
 */
data class ClientInstanceData
@ConstructorProperties(PROPERTY_NAME, PROPERTY_CLIENT_ID, PROPERTY_MANUFACTURER_ID, PROPERTY_MANUFACTURER_NAME, PROPERTY_OWNER_MAIL, PROPERTY_REGISTRATION_TIMESTAMP, PROPERTY_PLATFORM_PRODUCT_ID)
constructor(
    @field:JsonProperty(PROPERTY_NAME) val name: String,
    @field:JsonProperty(PROPERTY_CLIENT_ID) val clientId: String,
    @field:JsonProperty(PROPERTY_MANUFACTURER_ID) val manufacturerId: String,
    @field:JsonProperty(PROPERTY_MANUFACTURER_NAME) val manufacturerName: String,
    @field:JsonProperty(PROPERTY_OWNER_MAIL) val ownerMail: String,
    @field:JsonProperty(PROPERTY_REGISTRATION_TIMESTAMP) val registrationTimestamp: Long,
    @field:JsonProperty(PROPERTY_PLATFORM_PRODUCT_ID) val platformProductId: ProductId,
)
