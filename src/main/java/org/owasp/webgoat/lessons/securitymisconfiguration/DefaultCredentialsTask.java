/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securitymisconfiguration;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Task demonstrating exploitation of default credentials.
 * 
 * SECURITY LESSON:
 * Many applications come with default credentials (e.g., admin/admin, admin/password).
 * If these are not changed during setup, attackers can gain immediate access.
 * This task shows INSECURE behavior where default credentials are accepted.
 * Your job is to modify this to REJECT default credentials and only accept proper authentication.
 */
@RestController
@AssignmentHints({
    "securitymisconfiguration.task1.hint1",
    "securitymisconfiguration.task1.hint2"
})
public class DefaultCredentialsTask implements AssignmentEndpoint {

  // These are hardcoded default credentials (NOT secure in real applications)
  private static final String DEFAULT_USERNAME = "admin";
  private static final String DEFAULT_PASSWORD = "admin";

  @PostMapping(
      value = "/SecurityMisconfiguration/task1",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult login(
      @RequestParam(value = "username", required = false) String username,
      @RequestParam(value = "password", required = false) String password) {

    // Check if username or password is empty
    if (StringUtils.isBlank(username) || StringUtils.isBlank(password)) {
      return failed(this)
          .feedback("securitymisconfiguration.task1.failure.blank")
          .build();
    }
  // SECURITY ISSUE: This accepts admin/admin as valid credentials!
    // In a real application, default credentials should be:
    // 1. Changed during deployment
    // 2. Never accepted on login
    // 3. Logged and alerted (potential attack)
    if (DEFAULT_USERNAME.equals(username.trim()) && DEFAULT_PASSWORD.equals(password)) {
      return success(this)
          .feedback("securitymisconfiguration.task1.success")
          .output("User profile: staging admin (no MFA)")
          .build();
    }

    return failed(this)
        .feedback("securitymisconfiguration.task1.failure.invalid")
        .build();
  }
}
