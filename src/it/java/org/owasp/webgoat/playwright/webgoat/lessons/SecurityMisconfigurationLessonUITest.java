/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.playwright.webgoat.lessons;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;

import com.microsoft.playwright.Browser;
import org.assertj.core.api.Assertions;
import org.owasp.webgoat.playwright.webgoat.pages.lessons.SecurityMisconfigurationLessonPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.lessons.LessonName;
import org.owasp.webgoat.playwright.webgoat.PlaywrightTest;
import org.owasp.webgoat.playwright.webgoat.helpers.Authentication;

public class SecurityMisconfigurationLessonUITest extends PlaywrightTest {

  private SecurityMisconfigurationLessonPage lessonPage;

  @BeforeEach
  void navigateToLesson(Browser browser) {
    var lessonName = new LessonName("SecurityMisconfiguration");
    var page = Authentication.sylvester(browser);

    this.lessonPage = new SecurityMisconfigurationLessonPage(page);
    lessonPage.resetLesson(lessonName);
    lessonPage.open(lessonName);
  }

  @Test
  @DisplayName("Verify security misconfiguration protections")
  void shouldRejectLocalCredentialsAndHideSensitiveErrors() {
    lessonPage.navigateTo(2);
    lessonPage.fillDefaultCredentials("admin", "admin");
    lessonPage.submitTask1();
    assertThat(lessonPage.task1Output()).containsText("Authentication is unavailable");

    lessonPage.navigateTo(3);
    lessonPage.triggerSafeError();
    Assertions.assertThat(lessonPage.debugOutput()).isEqualTo("An unexpected error occurred.");
    Assertions.assertThat(lessonPage.requestProtectedConfig()).isEqualTo("ACCESS DENIED");
    lessonPage.submitTask2("any-token");
    assertThat(lessonPage.getAssignmentOutput()).containsText("The request is denied");

    lessonPage.navigateTo(4);

    var envJson = lessonPage.requestActuatorEnv();
    Assertions.assertThat(envJson).contains("systemApiKey");
    lessonPage.submitTask3(lessonPage.extractApiKey(envJson));
    assertThat(lessonPage.getAssignmentOutput()).containsText("Actuator endpoints secured");

    lessonPage.navigateTo(5);
    lessonPage.applyHardeningConfig();
    assertThat(lessonPage.getAssignmentOutput()).containsText("Configuration hardened");
  }
}
