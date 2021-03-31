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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType2;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 *
 * @author Rafal Lewczuk
 * @since 0.1.2
 */
public class OAuth2JwtGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String assertion;

	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2JwtGrantAuthenticationToken} using the provided parameters.
	 *
	 * @param assertion JWT assertion
	 * @param clientPrincipal the authenticated client principal
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2JwtGrantAuthenticationToken(String assertion, Authentication clientPrincipal,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType2.JWT_BEARER, clientPrincipal, additionalParameters);
		Assert.hasText(assertion, "assertion cannot be empty");
		this.assertion = assertion;
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}

	public String getAssertion() {
		return assertion;
	}

	public Set<String> getScopes() {
		return scopes;
	}
}
