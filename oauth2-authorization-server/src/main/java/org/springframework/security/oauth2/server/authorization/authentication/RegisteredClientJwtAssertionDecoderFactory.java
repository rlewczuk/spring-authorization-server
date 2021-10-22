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

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Creates JWT decoders for registered clients
 *
 * @author Rafal Lewczuk
 * @since 0.2.1
 */
final class RegisteredClientJwtAssertionDecoderFactory implements JwtDecoderFactory<RegisteredClientJwtAssertionAuthenticationContext> {

	private static final String CLIENT_ASSERTION_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7523#section-3";

	private static final Map<JwsAlgorithm, String> JCA_ALGORITHM_MAPPINGS;

	static {
		Map<JwsAlgorithm, String> mappings = new HashMap<>();
		mappings.put(MacAlgorithm.HS256, "HmacSHA256");
		mappings.put(MacAlgorithm.HS384, "HmacSHA384");
		mappings.put(MacAlgorithm.HS512, "HmacSHA512");
		JCA_ALGORITHM_MAPPINGS = Collections.unmodifiableMap(mappings);
	}

	private final Function<RegisteredClient, JwsAlgorithm> jwsAlgorithmResolver =
			rc -> rc.getClientSettings().getTokenEndpointSigningAlgorithm();

	private final Map<String, CachedJwtDecoder> cachedDecoders = new ConcurrentHashMap<>();

	@Override
	public JwtDecoder createDecoder(RegisteredClientJwtAssertionAuthenticationContext authenticationContext) {
		Assert.notNull(authenticationContext, "authenticationContext cannot be null");
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		OAuth2ClientAuthenticationToken clientAuthenticationToken = authenticationContext.getAuthentication();
		String cacheKey = clientAuthenticationToken.getIssuer() + "?client_id=" + registeredClient.getClientId();

		CachedJwtDecoder cachedDecoder = this.cachedDecoders.get(cacheKey);
		if (cachedDecoder != null && registeredClient.equals(cachedDecoder.registeredClient)) {
			return cachedDecoder.jwtDecoder;
		}

		cachedDecoder = new CachedJwtDecoder(buildDecoder(registeredClient), registeredClient);
		cachedDecoder.jwtDecoder.setJwtValidator(createTokenValidator(registeredClient, clientAuthenticationToken.getIssuer()));
		this.cachedDecoders.put(cacheKey, cachedDecoder);
		return cachedDecoder.jwtDecoder;
	}

	private NimbusJwtDecoder buildDecoder(RegisteredClient registeredClient) {
		JwsAlgorithm jwsAlgorithm = this.jwsAlgorithmResolver.apply(registeredClient);

		if (jwsAlgorithm != null && SignatureAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
			String jwkSetUrl = registeredClient.getClientSettings().getJwkSetUrl();
			if (!StringUtils.hasText(jwkSetUrl)) {
				OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"misconfigured client", CLIENT_ASSERTION_ERROR_URI);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			return NimbusJwtDecoder.withJwkSetUri(jwkSetUrl).jwsAlgorithm((SignatureAlgorithm) jwsAlgorithm).build();
		}

		if (jwsAlgorithm != null && MacAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
			String clientSecret = registeredClient.getClientSecret();
			if (!StringUtils.hasText(clientSecret)) {
				OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
						"misconfigured client", CLIENT_ASSERTION_ERROR_URI);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			SecretKeySpec secretKeySpec = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8),
					JCA_ALGORITHM_MAPPINGS.get(jwsAlgorithm));
			return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm) jwsAlgorithm).build();
		}

		OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
				"misconfigured client", CLIENT_ASSERTION_ERROR_URI);
		throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
	}

	private OAuth2TokenValidator<Jwt> createTokenValidator(RegisteredClient registeredClient, String fullTokenEndpointUri) {
		String clientId = registeredClient.getClientId();
		return new DelegatingOAuth2TokenValidator<>(
				new JwtClaimValidator<String>("iss", clientId::equals),      // RFC 7523 section 3 (iss)
				new JwtClaimValidator<String>("sub", clientId::equals),      // RFC 7523 section 3 (sub)
				new JwtClaimValidator<List<String>>("aud", l -> l.contains(fullTokenEndpointUri)), // RFC 7523 section 3 (aud)
				new JwtClaimValidator<>("exp", Objects::nonNull),            // RFC 7523 section 3 (exp != null)
				new JwtTimestampValidator()                                  // RFC 7523 section 3 (exp, nbf)
		);
		// TODO RFC 7523 section 3 #7: JWT may contain "jti" claim that provides unique identified for the token (OPTIONAL)
	}

	private static class CachedJwtDecoder {
		private final NimbusJwtDecoder jwtDecoder;
		private final RegisteredClient registeredClient;

		CachedJwtDecoder(NimbusJwtDecoder jwtDecoder, RegisteredClient registeredClient) {
			this.jwtDecoder = jwtDecoder;
			this.registeredClient = registeredClient;
		}
	}
}
