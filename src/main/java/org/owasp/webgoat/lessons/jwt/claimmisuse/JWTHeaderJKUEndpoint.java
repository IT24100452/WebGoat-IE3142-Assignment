/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

@RestController
@AssignmentHints({
    "jwt-jku-hint1",
    "jwt-jku-hint2",
    "jwt-jku-hint3",
    "jwt-jku-hint4",
    "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {

  private final String trustedJwksUrl;

  public JWTHeaderJKUEndpoint(
      @Value("${webgoat.jwt.jwks-url:}") String trustedJwksUrl) {
    this.trustedJwksUrl = trustedJwksUrl;
  }

  @PostMapping("/JWT/jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    }
    return "You are now following Tom";
  }

  @PostMapping("/JWT/jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    }

    try {
      // UPDATED: Fail closed if no trusted JWKS URL is configured.
      if (StringUtils.isBlank(trustedJwksUrl)) {
        return failed(this).feedback("jwt-invalid-token").build();
      }

      URI trustedUri = URI.create(trustedJwksUrl);
      if (!"https".equalsIgnoreCase(trustedUri.getScheme())
          || StringUtils.isBlank(trustedUri.getHost())
          || trustedUri.getUserInfo() != null
          || trustedUri.getFragment() != null) {
        return failed(this).feedback("jwt-invalid-token").build();
      }

      var decodedJwt = JWT.decode(token);
      String tokenJku = decodedJwt.getHeaderClaim("jku").asString();
      String keyId = decodedJwt.getKeyId();

      // UPDATED: Never fetch a key from a URL supplied only by the token.
      if (!trustedJwksUrl.equals(tokenJku)
          || StringUtils.isBlank(keyId)
          || !"RS256".equals(decodedJwt.getAlgorithm())) {
        return failed(this).feedback("jwt-invalid-token").build();
      }

      URL trustedUrl = trustedUri.toURL();
      var jwkProvider = new JwkProviderBuilder(trustedUrl).build();
      var jwk = jwkProvider.get(keyId);

      if (!(jwk.getPublicKey() instanceof RSAPublicKey)) {
        return failed(this).feedback("jwt-invalid-token").build();
      }

      RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
      Algorithm algorithm = Algorithm.RSA256(publicKey);
      JWT.require(algorithm).build().verify(decodedJwt);

      var usernameClaim = decodedJwt.getClaims().get("username");
      String username = usernameClaim == null ? null : usernameClaim.asString();

      if ("Jerry".equals(username)) {
        return failed(this).feedback("jwt-final-jerry-account").build();
      }
      if ("Tom".equals(username)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-final-not-tom").build();
    } catch (MalformedURLException
        | IllegalArgumentException
        | JWTVerificationException
        | JwkException e) {
      // UPDATED: Do not reveal URL, network, key-provider, or verification details.
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }
}
