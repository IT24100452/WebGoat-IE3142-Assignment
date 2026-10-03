/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class ProfileUploadFixTest extends LessonTest {

  @TempDir Path temporaryDirectory;

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void traversalNamesAreRejected() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "../John Doe"))
        .andExpect(status().is(200))
        .andExpect(jsonPath("$.assignment", CoreMatchers.equalTo("ProfileUploadFix")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void rejectsTraversalFormsBeforeWritingOutsideUploadRoot() {
    Path home = temporaryDirectory.resolve("sandbox").resolve("webgoat");
    Path outsideFile = temporaryDirectory.resolve("sandbox").resolve("outside.txt");
    ProfileUploadFix task = new ProfileUploadFix(home.toString());
    List<String> traversalNames =
        List.of(
            "../outside.txt",
            "../../../outside.txt",
            "%2e%2e%2foutside.txt",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2foutside.txt",
            "....//outside.txt",
            "..\\outside.txt",
            "..\\..\\..\\outside.txt",
            "%252e%252e%255coutside.txt");

    for (String name : traversalNames) {
      AttackResult result =
          task.uploadFileHandler(
              new MockMultipartFile(
                  "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes()),
              name,
              "test");
      Assertions.assertThat(result.assignmentSolved()).isFalse();
    }

    Assertions.assertThat(outsideFile).doesNotExist();
    Assertions.assertThat(home.resolve("PathTraversal").resolve("test")).doesNotExist();
  }

  @Test
  void normalUpdate() throws Exception {
    var profilePicture =
        new MockMultipartFile(
            "uploadedFileFix", "picture.jpg", "text/plain", "an image".getBytes());

    mockMvc
        .perform(
            MockMvcRequestBuilders.multipart("/PathTraversal/profile-upload-fix")
                .file(profilePicture)
                .param("fullNameFix", "John Doe"))
        .andExpect(status().is(200))
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.containsString("test\\" + File.separator + "John Doe")))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}
