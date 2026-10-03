/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.HashMap;
import java.util.Map;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class JWTHeaderKIDEndpointTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void rejectsSqlInjectionInKeyIdentifier() throws Exception {
    String token =
        createToken(
            "hacked' UNION select 'deletingTom' from INFORMATION_SCHEMA.SYSTEM_USERS --",
            SignatureAlgorithm.HS512);

    expectInvalidToken(token);
  }

  @Test
  void rejectsEmptyKeyIdentifier() throws Exception {
    expectInvalidToken(createToken(" ", SignatureAlgorithm.HS512));
  }

  @Test
  void rejectsNonStringKeyIdentifier() throws Exception {
    Map<String, Object> kid = Map.of("id", "webgoat_key");
    expectInvalidToken(createToken(kid, SignatureAlgorithm.HS512));
  }

  @Test
  void rejectsUnsupportedAlgorithm() throws Exception {
    expectInvalidToken(createToken("webgoat_key", SignatureAlgorithm.HS256));
  }

  private String createToken(Object kid, SignatureAlgorithm algorithm) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    return Jwts.builder()
        .setHeaderParam("kid", kid)
        .setClaims(claims)
        .signWith(algorithm, "deletingTom")
        .compact();
  }

  private void expectInvalidToken(String token) throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}
