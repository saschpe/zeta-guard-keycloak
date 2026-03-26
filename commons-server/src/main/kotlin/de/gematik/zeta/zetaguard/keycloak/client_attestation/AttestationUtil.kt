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
package de.gematik.zeta.zetaguard.keycloak.client_attestation

import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash

/**
 * Calculate attestation challenge = SHA-256( SHA-256(pubKey) || nonce ). (BASE64 encoded)
 *
 * According to https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.5.1
 *
 * @param nonce Server-provided nonce bytes
 * @param jwkThumbPrint Raw client JWK thumb print according to RFC 7638
 * @return BASE64-encoded attestation challenge
 */
fun calculateAttestationChallenge(jwkThumbPrint: ByteArray, nonce: ByteArray): String = toHash(jwkThumbPrint, nonce).toBase64()
