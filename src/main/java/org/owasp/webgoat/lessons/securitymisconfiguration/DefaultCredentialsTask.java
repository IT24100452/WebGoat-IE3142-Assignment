/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securitymisconfiguration;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Task demonstrating fail-closed authentication when no provider is configured. */
@RestController
@AssignmentHints({
    "securitymisconfiguration.task1.hint1",
    "securitymisconfiguration.task1.hint2"
})
public class DefaultCredentialsTask implements AssignmentEndpoint {

  @PostMapping(
      value = "/SecurityMisconfiguration/task1",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  @ResponseBody
  public AttackResult login(
      @RequestParam(value = "username", required = false) String username,
      @RequestParam(value = "password", required = false) String password) {

    if (username == null || username.isBlank() || password == null || password.isBlank()) {
      return failed(this)
          .feedback("securitymisconfiguration.task1.failure.blank")
          .build();
    }

    return failed(this)
        .feedback("securitymisconfiguration.task1.failure.invalid")
        .build();
  }
}
