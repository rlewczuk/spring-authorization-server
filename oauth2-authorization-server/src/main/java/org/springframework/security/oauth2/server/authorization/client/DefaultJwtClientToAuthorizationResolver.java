package org.springframework.security.oauth2.server.authorization.client;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.security.Principal;

public class DefaultJwtClientToAuthorizationResolver implements JwtClientToAuthorizationResolver {
	@Override
	public OAuth2Authorization resolve(Jwt jwt, RegisteredClient registeredClient) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(jwt.getSubject())
				.attribute(Principal.class.getName(), new UsernamePasswordAuthenticationToken(jwt.getSubject(), null)) // TODO what can be used here ?
				.build();
	}
}
