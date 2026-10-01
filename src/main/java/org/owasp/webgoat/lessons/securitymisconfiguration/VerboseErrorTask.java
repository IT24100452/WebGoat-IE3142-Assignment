/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securitymisconfiguration;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Task exposing verbose stack traces leaking sensitive configuration. */
@RestController
@AssignmentHints({
    "securitymisconfiguration.task2.hint1",
    "securitymisconfiguration.task2.hint2"
})
public class VerboseErrorTask implements AssignmentEndpoint {

     @GetMapping(value = "/SecurityMisconfiguration/task2/trigger", produces = MediaType.TEXT_PLAIN_VALUE)
  public ResponseEntity<String> triggerError() {
    // UPDATED: Return a generic error; do not expose stack traces or configuration.
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Request failed");
  }

  @GetMapping(value = "/SecurityMisconfiguration/task2/config", produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<String> fetchConfig(
      @RequestParam(value = "token", required = false) String token) {
    // UPDATED: Never use a leaked/static token to grant access to configuration.
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("ACCESS DENIED");
  }

  @PostMapping(
      value = "/SecurityMisconfiguration/task2",
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
  public AttackResult submitToken(@RequestParam("token") String token) {
    if (token == null || token.isBlank()) {
      return failed(this)
          .feedback("securitymisconfiguration.task2.failure.blank")
          .build();
    }

    // UPDATED: There is no hard-coded leaked token that can mark this task successful.
    return failed(this)
        .feedback("securitymisconfiguration.task2.failure.invalid")
        .build();
  }
}
  
