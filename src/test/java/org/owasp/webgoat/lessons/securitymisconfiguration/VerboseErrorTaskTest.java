/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securitymisconfiguration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class VerboseErrorTaskTest {

  private VerboseErrorTask task;

  @BeforeEach
  void setUp() {
    task = new VerboseErrorTask();
  }

  @Test
  void triggerShouldReturnOnlyAGenericFailure() {
    var response = task.triggerError();

    assertThat(response.getStatusCode().value()).isEqualTo(500);
    assertThat(response.getBody()).isEqualTo("An unexpected error occurred.");
    assertThat(response.getBody()).doesNotContain("Exception", "ENVIRONMENT", "PASSWORD", "TOKEN");
  }

  @Test
  void shouldFailWhenTokenMissing() {
    AttackResult result = task.submitToken("");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task2.failure.blank");
  }

  @Test
  void shouldFailWithIncorrectToken() {
    AttackResult result = task.submitToken("WRONG");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task2.failure.invalid");
  }


  @Test
  void configEndpointShouldDenyRequestsEvenWhenATokenIsProvided() throws Exception {
    MockMvcBuilders.standaloneSetup(task)
        .build()
        .perform(
            get("/SecurityMisconfiguration/task2/config")
                .param("token", "any-token"))
        .andExpect(status().isForbidden())
        .andExpect(content().string("ACCESS DENIED"));
  }

  @Test
  void shouldNeverPassWhenATokenIsProvided() {
    AttackResult result = task.submitToken("any-token");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task2.failure.invalid");
  }
}
