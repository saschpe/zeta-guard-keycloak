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
package de.gematik.zeta.zetaguard.keycloak.proxy

import java.lang.reflect.Method

interface MethodAugmenter<T> {
  /**
   * @param delegate The original object being wrapped
   * @param method The method being called
   * @param args The arguments passed to the method
   * @return The result of the call
   */
  fun execute(delegate: T, method: Method, args: Array<out Any?>): Any?

  /**
   * Check if given method behaviour has to be altered
   *
   * @return true, if method behaviour has to be replaced by a call to [execute]
   */
  fun isAugmentedMethod(method: Method): Boolean
}
