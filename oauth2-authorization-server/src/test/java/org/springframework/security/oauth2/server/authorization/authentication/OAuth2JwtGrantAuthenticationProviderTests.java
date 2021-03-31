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

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.JwtClientToAuthorizationResolver;
import org.springframework.security.oauth2.server.authorization.client.JwtToRegisteredClientResolver;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.security.Principal;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OAuth2JwtGrantAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;
	private JwtToRegisteredClientResolver clientResolver;
	private JwtClientToAuthorizationResolver authResolver;
	private JwtEncoder jwtEncoder;
	private JwtDecoder jwtDecoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;
	private OAuth2JwtGrantAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.clientResolver = mock(JwtToRegisteredClientResolver.class);
		this.authResolver = mock(JwtClientToAuthorizationResolver.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.jwtDecoder = mock(JwtDecoder.class);
		this.authenticationProvider = new OAuth2JwtGrantAuthenticationProvider(
				this.authorizationService, this.clientResolver, this.authResolver, this.jwtDecoder, this.jwtEncoder);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		this.authenticationProvider.setJwtCustomizer(this.jwtCustomizer);
	}

	@Test
	public void constructorWithAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2JwtGrantAuthenticationProvider(
				null, this.clientResolver, this.authResolver, this.jwtDecoder, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWithClientResolverNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2JwtGrantAuthenticationProvider(
				this.authorizationService, null, this.authResolver, this.jwtDecoder, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientResolver cannot be null");
	}

	@Test
	public void constructorWithAuthorizationResolverNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2JwtGrantAuthenticationProvider(
				this.authorizationService, this.clientResolver, null, this.jwtDecoder, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtClientToAuthorizationResolver cannot be null");
	}

	@Test
	public void constructorWithJwtDecoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2JwtGrantAuthenticationProvider(
				this.authorizationService, this.clientResolver, this.authResolver, null, this.jwtEncoder))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtDecoder cannot be null");
	}

	@Test
	public void constructorWithJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2JwtGrantAuthenticationProvider(
				this.authorizationService, this.clientResolver, this.authResolver, this.jwtDecoder, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtEncoder cannot be null");
	}

	@Test
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setJwtCustomizer(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jwtCustomizer cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2JwtGrantAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isFalse();
	}

	@Test
	public void grantWithNonAuthenticatedClientPrincipalThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.BASIC, null);
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		when(this.jwtDecoder.decode(any())).thenThrow(new RuntimeException("should not happen"));
	}

	@Test
	public void grantWithNonDecodingJwtThenThrowInvalidGrant() {
		AnonymousAuthenticationToken anonToken = new AnonymousAuthenticationToken(
				"1b9f8ddc-445b-43a1-b199-e2664f2dbbd7", "anonymousUser",
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", anonToken, null, null);
		when(this.jwtDecoder.decode(any())).thenThrow(new JwtException("jwt verification failed"));
		when(this.clientResolver.resolve(any())).thenThrow(new RuntimeException("should not happen!"));
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	// TODO whenClientPrincipalDoesNotMatchThenThrowInvalidGrant

	@Test
	public void grantWithNonResolvingClientThenThrowInvalidGrant() {
		AnonymousAuthenticationToken anonToken = new AnonymousAuthenticationToken(
				"1b9f8ddc-445b-43a1-b199-e2664f2dbbd7", "anonymousUser",
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", anonToken, null, null);
		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(null);
		when(this.authResolver.resolve(any(), any())).thenThrow(new RuntimeException("should not happen"));
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void grantWithRegisteredClientBadGrantThenThrowUnauthorizedClient() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.build();
		AnonymousAuthenticationToken anonToken = new AnonymousAuthenticationToken(
				"1b9f8ddc-445b-43a1-b199-e2664f2dbbd7", "anonymousUser",
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", anonToken, null, null);
		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(registeredClient);
		when(this.authResolver.resolve(any(), any())).thenThrow(new RuntimeException("should not happen"));
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void whenAuthorizationDoesNotResolveThenThrowInvalidGrant() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.build();
		AnonymousAuthenticationToken anonToken = new AnonymousAuthenticationToken(
				"1b9f8ddc-445b-43a1-b199-e2664f2dbbd7", "anonymousUser",
				Collections.singletonList(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", anonToken, null, null);
		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(registeredClient);
		when(this.authResolver.resolve(any(), any())).thenReturn(null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.authorizationGrantTypes(grantTypes -> grantTypes.remove(AuthorizationGrantType2.JWT_BEARER))
				.build();
		// TODO what about anonymous principals ?
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", clientPrincipal, null, null);
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));

		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(registeredClient);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void whenRequestWithBadScopesThenThrowInvalidScopes() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", clientPrincipal, Collections.singleton("bad"), null);
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));
		OAuth2Authorization userAuth = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("client-2")
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken(jwt.getSubject(), null))
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.build();

		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(registeredClient);
		when(this.authResolver.resolve(any(), any())).thenReturn(userAuth);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(jwt);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError())
				.extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void whenAllArgumentsValidThenIssueAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2JwtGrantAuthenticationToken authentication =
				new OAuth2JwtGrantAuthenticationToken("xxx", clientPrincipal, null, null);
		Jwt jwt = new Jwt("xx", Instant.now().minusSeconds(30), Instant.now().plusSeconds(300),
				map("kid", "123"),
				map("iss", "client-2", "sub", "client-2"));
		OAuth2Authorization userAuth = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName("client-2")
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken(jwt.getSubject(), null))
				.authorizationGrantType(AuthorizationGrantType2.JWT_BEARER)
				.build();

		when(this.jwtDecoder.decode(any())).thenReturn(jwt);
		when(this.clientResolver.resolve(any())).thenReturn(registeredClient);
		when(this.authResolver.resolve(any(), any())).thenReturn(userAuth);
		when(this.jwtEncoder.encode(any(), any())).thenReturn(jwt);

		Authentication auth = this.authenticationProvider.authenticate(authentication);
		assertThat(auth).isNotNull();
	}

	// TODO is there similar function somewhere in accessible Spring libraries ?
	private static <K, V> Map<K, V> map(Object...args) {
		HashMap<K, V> m = new HashMap<>();
		for (int i = 1; i < args.length; i+=2) {
			m.put((K) args[i-1], (V) args[i]);
		}
		return m;
	}
}
