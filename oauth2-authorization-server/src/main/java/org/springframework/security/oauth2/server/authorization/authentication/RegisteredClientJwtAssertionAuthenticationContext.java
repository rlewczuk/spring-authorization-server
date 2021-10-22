/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * An {@link OAuth2AuthenticationContext} that holds {@link RegisteredClient}. Used in {@link RegisteredClientJwtAssertionDecoderFactory}.
 *
 * @author Rafal Lewczuk
 * @since 0.2.1
 * @see OAuth2AuthenticationContext
 * @see RegisteredClient
 * @see RegisteredClientJwtAssertionDecoderFactory
 * @see OAuth2ClientAuthenticationProvider
 */
final class RegisteredClientJwtAssertionAuthenticationContext extends OAuth2AuthenticationContext {

	private RegisteredClientJwtAssertionAuthenticationContext(Map<Object, Object> context) {
		super(context);
	}

	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	static RegisteredClientJwtAssertionAuthenticationContext build(RegisteredClient registeredClient, OAuth2ClientAuthenticationToken clientAuthenticationToken) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		Assert.notNull(clientAuthenticationToken, "clientAuthentication cannot be null");
		Map<Object, Object> context = new HashMap<>();
		context.put(RegisteredClient.class, registeredClient);
		context.put(Authentication.class, clientAuthenticationToken);
		return new RegisteredClientJwtAssertionAuthenticationContext(context);
	}
}
