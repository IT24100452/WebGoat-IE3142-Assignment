/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;
import static io.jsonwebtoken.SignatureAlgorithm.RS256;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.tomakehurst.wiremock.WireMockServer;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.assertj.core.api.Assertions.assertThat;

class JWTHeaderJKUEndpointTest extends LessonTest {
  private static final String TRUSTED_JWKS_URL = "https://trusted.example/jwks";

  private KeyPair keyPair;
  private WireMockServer jwksServer;

  @BeforeEach
  void setup() throws Exception {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    this.keyPair = keyPairGenerator.generateKeyPair();
    this.jwksServer = new WireMockServer(options().dynamicPort());
    this.jwksServer.start();
  }

  @AfterEach
  void tearDown() {
    this.jwksServer.stop();
  }

  @Test
  void failsClosedWhenNoTrustedJwksSourceIsConfigured() throws Exception {
    String token = createRsaToken(untrustedUrl());

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("jwt-invalid-token"))));
    jwksServer.verify(0, getRequestedFor(urlEqualTo("/jwks")));
  }

  @Test
  void rejectsTokenControlledUrlWhenASeparateTrustedSourceIsConfigured() {
    JWTHeaderJKUEndpoint endpoint = new JWTHeaderJKUEndpoint(TRUSTED_JWKS_URL);
    AttackResult result = endpoint.resetVotes(createRsaToken(untrustedUrl()));

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("jwt-invalid-token");
    jwksServer.verify(0, getRequestedFor(urlEqualTo("/jwks")));
  }

  @Test
  void rejectsUnsupportedAlgorithmBeforeUsingConfiguredJwksSource() {
    JWTHeaderJKUEndpoint endpoint = new JWTHeaderJKUEndpoint(TRUSTED_JWKS_URL);
    String token = createHmacToken(TRUSTED_JWKS_URL);

    AttackResult result = endpoint.resetVotes(token);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("jwt-invalid-token");
  }

  @Test
  void rejectsConfiguredHttpJwksSource() {
    String httpJwksUrl = untrustedUrl();
    JWTHeaderJKUEndpoint endpoint = new JWTHeaderJKUEndpoint(httpJwksUrl);

    AttackResult result = endpoint.resetVotes(createRsaToken(httpJwksUrl));

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("jwt-invalid-token");
    jwksServer.verify(0, getRequestedFor(urlEqualTo("/jwks")));
  }

  private String createRsaToken(String jku) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    return Jwts.builder()
        .setHeaderParam("jku", jku)
        .setHeaderParam("kid", "key-1")
        .setClaims(claims)
        .signWith(RS256, this.keyPair.getPrivate())
        .compact();
  }

  private String untrustedUrl() {
    return "http://localhost:" + jwksServer.port() + "/jwks";
  }

  private String createHmacToken(String jku) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    return Jwts.builder()
        .setHeaderParam("jku", jku)
        .setHeaderParam("kid", "key-1")
        .setClaims(claims)
        .signWith(HS256, "not-a-trusted-rsa-key")
        .compact();
  }
}
