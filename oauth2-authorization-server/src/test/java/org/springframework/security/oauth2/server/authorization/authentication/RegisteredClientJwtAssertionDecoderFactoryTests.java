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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link RegisteredClientJwtAssertionDecoderFactory}
 *
 * @author Rafal Lewczuk
 */
public class RegisteredClientJwtAssertionDecoderFactoryTests {

	private JwtDecoderFactory<RegisteredClientJwtAssertionAuthenticationContext> registeredClientDecoderFactory;

	@Before
	public void setUp() {
		this.registeredClientDecoderFactory = new RegisteredClientJwtAssertionDecoderFactory();
	}

	@Test
	public void createDecoderWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> registeredClientDecoderFactory.createDecoder(null))
				.withMessage("authenticationContext cannot be null");
	}

	@Test
	public void createDecoderWhenClientAuthenticationMethodNotSupportedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);
		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(context))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithClientSecretJwtWhenClientSecretNullThenThrowOAuth2Exception() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientSecret(null)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build())
				.build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);

		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(context))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithClientSecretJwtClientThenReturnDecoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF")
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build())
				.build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);

		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(context);

		assertThat(jwtDecoder).isNotNull();
	}

	@Test
	public void createDecoderWithClientSecretJwtTwiceThenReturnCachedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF")
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build());
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context1 = RegisteredClientJwtAssertionAuthenticationContext.build(
				registeredClientBuilder.build(), token);
		RegisteredClientJwtAssertionAuthenticationContext context2 = RegisteredClientJwtAssertionAuthenticationContext.build(
				registeredClientBuilder.build(), token);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(context1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(context2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isSameAs(decoder1);
	}

	@Test
	public void createDecoderWithClientSecretJwtAndSecondWithChangedAlgorithmThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret("0123456789abcdef0123456789ABCDEF");
		RegisteredClient client1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build()).build();
		RegisteredClient client2 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS512).build()).build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context1 = RegisteredClientJwtAssertionAuthenticationContext.build(
				client1, token);
		RegisteredClientJwtAssertionAuthenticationContext context2 = RegisteredClientJwtAssertionAuthenticationContext.build(
				client2, token);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(context1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(context2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithClientSecretJwtAndSecondWithChangedSecretThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSettings(ClientSettings.builder().tokenEndpointSigningAlgorithm(MacAlgorithm.HS256).build());
		RegisteredClient client1 = registeredClientBuilder.clientSecret("0123456789abcdef0123456789ABCDEF").build();
		RegisteredClient client2 = registeredClientBuilder.clientSecret("0123456789ABCDEF0123456789abcdef").build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context1 = RegisteredClientJwtAssertionAuthenticationContext.build(client1, token);
		RegisteredClientJwtAssertionAuthenticationContext context2 = RegisteredClientJwtAssertionAuthenticationContext.build(client2, token);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(context1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(context2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtMissingJwksUrlThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(ClientSettings.builder()
						.tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256).build())
				.build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);
		assertThatThrownBy(() -> this.registeredClientDecoderFactory.createDecoder(context))
				.isInstanceOf(OAuth2AuthenticationException.class);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtThenReturnDecoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(ClientSettings.builder()
						.tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256).jwkSetUrl("https://client.example.com/jwks").build())
				.build();
		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);
		JwtDecoder jwtDecoder = this.registeredClientDecoderFactory.createDecoder(context);
		assertThat(jwtDecoder).isNotNull();
	}

	@Test
	public void createDecoderWithPrivateKeyJwtAndSecondWithChangedAlgorithmThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

		RegisteredClient client1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite.com/jwks").build()).build();
		RegisteredClient client2 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS512)
						.jwkSetUrl("https://keysite.com/jwks").build()).build();

		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context1 = RegisteredClientJwtAssertionAuthenticationContext.build(client1, token);
		RegisteredClientJwtAssertionAuthenticationContext context2 = RegisteredClientJwtAssertionAuthenticationContext.build(client2, token);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(context1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(context2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtAndSecondWithChangedJwksUrlThenReturnRecreatedDecoder() {
		RegisteredClient.Builder registeredClientBuilder = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

		RegisteredClient client1 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite1.com/jwks").build()).build();
		RegisteredClient client2 = registeredClientBuilder.clientSettings(
				ClientSettings.builder().tokenEndpointSigningAlgorithm(SignatureAlgorithm.RS256)
						.jwkSetUrl("https://keysite2.com/jwks").build()).build();

		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context1 = RegisteredClientJwtAssertionAuthenticationContext.build(client1, token);
		RegisteredClientJwtAssertionAuthenticationContext context2 = RegisteredClientJwtAssertionAuthenticationContext.build(client2, token);

		JwtDecoder decoder1 = this.registeredClientDecoderFactory.createDecoder(context1);
		JwtDecoder decoder2 = this.registeredClientDecoderFactory.createDecoder(context2);

		assertThat(decoder1).isNotNull();
		assertThat(decoder2).isNotNull();
		assertThat(decoder1).isNotSameAs(decoder2);
	}

	@Test
	public void createDecoderWithPrivateKeyJwtNullAlgorithmThenReturnDefaultRS256Decoder() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.clientSettings(
						ClientSettings.builder()
								.jwkSetUrl("https://keysite1.com/jwks")
								.build())
				.build();

		OAuth2ClientAuthenticationToken token = new OAuth2ClientAuthenticationToken(
				"https://auth-server/oauth2/token", "client-1", ClientAuthenticationMethod.CLIENT_SECRET_JWT, "jwt", null);
		RegisteredClientJwtAssertionAuthenticationContext context = RegisteredClientJwtAssertionAuthenticationContext.build(registeredClient, token);
		JwtDecoder decoder = this.registeredClientDecoderFactory.createDecoder(context);
		assertThat(decoder).isNotNull();
	}

}
