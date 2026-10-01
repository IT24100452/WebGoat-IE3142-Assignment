/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.SQLException;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;

@RestController
@AssignmentHints({
    "jwt-kid-hint1",
    "jwt-kid-hint2",
    "jwt-kid-hint3",
    "jwt-kid-hint4",
    "jwt-kid-hint5",
    "jwt-kid-hint6"
})
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {
  private final LessonDataSource dataSource;

  private JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/JWT/kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    }
    return "You are now following Tom";
  }

  @PostMapping("/JWT/kid/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    }

    try {
      Jwt jwt =
          Jwts.parser()
              .setSigningKeyResolver(
                  new SigningKeyResolverAdapter() {
                    @Override
                    public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                      // UPDATED: Reject any signing algorithm other than the expected one.
                      if (!"HS512".equals(header.getAlgorithm())) {
                        return null;
                      }

                      Object kidValue = header.get("kid");
                      if (!(kidValue instanceof String)) {
                        return null;
                      }

                      String kid = (String) kidValue;

                      // UPDATED: Reject empty or malformed key identifiers.
                      if (kid.isBlank()
                          || kid.length() > 128
                          || !kid.matches("[A-Za-z0-9._-]+")) {
                        return null;
                      }

                      try (var connection = dataSource.getConnection();
                          var statement =
                              connection.prepareStatement(
                                  "SELECT key FROM jwt_keys WHERE id = ?")) {
                        // UPDATED: Bind kid as a SQL value, not SQL syntax.
                        statement.setString(1, kid);

                        try (var resultSet = statement.executeQuery()) {
                          if (!resultSet.next()) {
                            return null;
                          }

                          String storedKey = resultSet.getString(1);
                          return storedKey == null ? null : TextCodec.BASE64.decode(storedKey);
                        }
                      } catch (SQLException e) {
                        // UPDATED: Do not expose database details through the response.
                        throw new IllegalStateException("Unable to resolve signing key", e);
                      }
                    }
                  })
              .parseClaimsJws(token);

      Claims claims = (Claims) jwt.getBody();
      String username = claims.get("username", String.class);

      if ("Jerry".equals(username)) {
        return failed(this).feedback("jwt-final-jerry-account").build();
      }
      if ("Tom".equals(username)) {
        return success(this).build();
      }
      return failed(this).feedback("jwt-final-not-tom").build();
    } catch (JwtException | IllegalArgumentException | IllegalStateException e) {
      // UPDATED: Do not disclose token parser, database, or key-resolution details.
      return failed(this).feedback("jwt-invalid-token").build();
    }
  }
}
