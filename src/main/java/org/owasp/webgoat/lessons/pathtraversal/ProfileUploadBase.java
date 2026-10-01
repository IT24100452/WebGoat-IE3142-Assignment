/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private static final Pattern ENCODED_PATH_CHARACTER = Pattern.compile("(?i)%(?:2e|2f|5c|25)");

  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  // The vulnerable lesson routes retain this path; ProfileUploadFix uses executeSafely.
  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser(username);

    try {
      var uploadedFile = new File(uploadDirectory, fullName);
      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      if (attemptWasMade(uploadDirectory, uploadedFile)) {
        return solvedIt(uploadedFile);
      }
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();
    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  protected AttackResult executeSafely(MultipartFile file, String fullName, String username) {
    if (file == null || file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (!StringUtils.hasLength(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }
    if (!isSafePathComponent(username) || !isSafeFileName(fullName)) {
      return traversalRejected();
    }

    try {
      File uploadDirectory = createSafeDirectoryForUser(username);
      Path realUploadDirectory = uploadDirectory.toPath().toRealPath();
      Path destination = realUploadDirectory.resolve(fullName).normalize();
      if (!destination.startsWith(realUploadDirectory)
          || !realUploadDirectory.equals(destination.getParent())
          || Files.isSymbolicLink(destination)) {
        return traversalRejected();
      }

      try (InputStream input = file.getInputStream();
          OutputStream output =
              Files.newOutputStream(
                  destination,
                  StandardOpenOption.CREATE,
                  StandardOpenOption.TRUNCATE_EXISTING,
                  StandardOpenOption.WRITE,
                  LinkOption.NOFOLLOW_LINKS)) {
        input.transferTo(output);
      }

      if (attemptWasMade(uploadDirectory, destination.toFile())) {
        return solvedIt(destination.toFile());
      }
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(destination.toFile().getAbsoluteFile())
          .build();
    } catch (IOException | InvalidPathException e) {
      return traversalRejected();
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    var uploadDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  private File createSafeDirectoryForUser(String username) throws IOException {
    Path configuredRoot = Path.of(webGoatHomeDirectory).toAbsolutePath().normalize();
    Files.createDirectories(configuredRoot);
    Path realConfiguredRoot = configuredRoot.toRealPath();

    Path uploadRoot = realConfiguredRoot.resolve("PathTraversal");
    Files.createDirectories(uploadRoot);
    Path realUploadRoot = uploadRoot.toRealPath();
    if (!realConfiguredRoot.equals(realUploadRoot.getParent())) {
      throw new IOException("Invalid upload root");
    }

    Path userDirectory = realUploadRoot.resolve(username).normalize();
    if (!realUploadRoot.equals(userDirectory.getParent())
        || Files.isSymbolicLink(userDirectory)) {
      throw new IOException("Invalid user upload directory");
    }
    if (Files.exists(userDirectory, LinkOption.NOFOLLOW_LINKS)) {
      FileSystemUtils.deleteRecursively(userDirectory.toFile());
    }
    Files.createDirectories(userDirectory);
    Path realUserDirectory = userDirectory.toRealPath();
    if (!realUploadRoot.equals(realUserDirectory.getParent())) {
      throw new IOException("Invalid user upload directory");
    }
    return realUserDirectory.toFile();
  }

  private static boolean isSafePathComponent(String value) {
    return value != null
        && !value.isBlank()
        && !".".equals(value)
        && !"..".equals(value)
        && value.indexOf('/') < 0
        && value.indexOf('\\') < 0
        && value.chars().noneMatch(Character::isISOControl);
  }

  private static boolean isSafeFileName(String value) {
    if (!isSafePathComponent(value)
        || ENCODED_PATH_CHARACTER.matcher(value).find()
        || value.indexOf(':') >= 0
        || value.endsWith(".")
        || value.endsWith(" ")) {
      return false;
    }

    // UPDATED: Reject Windows device names as upload filenames.
    return !value.matches("(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?$");
  }

  private AttackResult traversalRejected() {
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .build();
  }

  private boolean attemptWasMade(File expectedUploadDirectory, File uploadedFile)
      throws IOException {
    return !expectedUploadDirectory
        .getCanonicalPath()
        .equals(uploadedFile.getParentFile().getCanonicalPath());
  }

  private AttackResult solvedIt(File uploadedFile) throws IOException {
    if (uploadedFile.getCanonicalFile().getParentFile().getName().endsWith("PathTraversal")) {
      return success(this).build();
    }
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .feedbackArgs(uploadedFile.getCanonicalPath())
        .build();
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    var profilePictureDirectory = new File(this.webGoatHomeDirectory, "/PathTraversal/" + username);
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
