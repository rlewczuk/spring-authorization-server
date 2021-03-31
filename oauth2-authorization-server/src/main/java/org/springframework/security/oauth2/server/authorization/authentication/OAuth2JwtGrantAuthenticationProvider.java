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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.JwtClientToAuthorizationResolver;
import org.springframework.security.oauth2.server.authorization.client.JwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class OAuth2JwtGrantAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2AuthorizationService authorizationService;
	private final JwtToRegisteredClientResolver registeredClientResolver;
	private final JwtClientToAuthorizationResolver jwtClientToAuthorizationResolver;
	private final JwtDecoder jwtDecoder;
	private final JwtEncoder jwtEncoder;

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private ProviderSettings providerSettings;

	public OAuth2JwtGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			JwtToRegisteredClientResolver registeredClientResolver,
			JwtClientToAuthorizationResolver jwtClientToAuthorizationResolver,
			JwtDecoder jwtDecoder, JwtEncoder jwtEncoder) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(registeredClientResolver, "registeredClientResolver cannot be null");
		Assert.notNull(jwtClientToAuthorizationResolver, "jwtClientToAuthorizationResolver cannot be null");
		Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.authorizationService = authorizationService;
		this.registeredClientResolver = registeredClientResolver;
		this.jwtClientToAuthorizationResolver = jwtClientToAuthorizationResolver;
		this.jwtDecoder = jwtDecoder;
		this.jwtEncoder = jwtEncoder;
	}

	public final void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	@Autowired(required = false)
	protected void setProviderSettings(ProviderSettings providerSettings) {
		this.providerSettings = providerSettings;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2JwtGrantAuthenticationToken jwtAuthentication = (OAuth2JwtGrantAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = null;

		if (jwtAuthentication.getPrincipal() != null &&
				OAuth2ClientAuthenticationToken.class.isAssignableFrom(jwtAuthentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
			if (!clientPrincipal.isAuthenticated()) {
				throwAuthError(OAuth2ErrorCodes.INVALID_CLIENT);
			}
		}

		Jwt jwt = null;

		try {
			jwt = jwtDecoder.decode(jwtAuthentication.getAssertion());
		} catch (JwtException e) {
			throwAuthError(OAuth2ErrorCodes.INVALID_GRANT);
		}

		RegisteredClient registeredClient = registeredClientResolver.resolve(jwt);
		if (registeredClient == null ) {
			throwAuthError(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (clientPrincipal != null &&
				!clientPrincipal.getRegisteredClient().getClientId().equals(registeredClient.getClientId())) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT)); // TODO test
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType2.JWT_BEARER)) {
			throwAuthError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2Authorization userAuth = jwtClientToAuthorizationResolver.resolve(jwt, registeredClient);
		if (userAuth == null) {
			throwAuthError(OAuth2ErrorCodes.INVALID_GRANT);
		}

		Set<String> authorizedScopes = registeredClient.getScopes();		// Default to configured scopes
		if (!CollectionUtils.isEmpty(jwtAuthentication.getScopes())) {
			Set<String> unauthorizedScopes = jwtAuthentication.getScopes().stream()
					.filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
					.collect(Collectors.toSet());
			if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
				throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE)); // TODO test
			}
			authorizedScopes = new LinkedHashSet<>(jwtAuthentication.getScopes());
		}

		String issuer = this.providerSettings != null ? this.providerSettings.issuer() : null;

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, userAuth.getPrincipalName(), authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.authorizationGrant(jwtAuthentication)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), authorizedScopes);

		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(userAuth.getPrincipalName())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
				.build();
		// @formatter:on

		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2JwtGrantAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private void throwAuthError(String reason) {
		throw new OAuth2AuthenticationException(new OAuth2Error(reason));
	}

}
