/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static java.util.Comparator.comparing;
import static org.springframework.http.MediaType.ALL_VALUE;

import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.TimeZone;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import java.util.regex.Pattern;

/** Controller for uploading a file */
@Controller
@Slf4j
public class FileServer {

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

  /** Messages shown on the files page, the upload redirects to it with one of them. */
  static final String UPLOAD_SUCCESSFUL = "File uploaded successful";

  static final String NOTHING_TO_UPLOAD = "Nothing to upload";
  static final String UPLOAD_TOO_LARGE = "File is too large to upload";

  private static final Pattern ENCODED_PATH_CHARACTER = Pattern.compile("(?i)%(?:2e|2f|5c|25)");

  @Value("${webwolf.fileserver.location}")
  private String fileLocation;

  @Value("${server.address}")
  private String server;

  @Value("${server.servlet.context-path}")
  private String contextPath;

  @Value("${server.port}")
  private int port;

  @RequestMapping(
      path = "/file-server-location",
      consumes = ALL_VALUE,
      produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String getFileLocation() {
    return fileLocation;
  }

  @PostMapping(value = "/fileupload")
  public ModelAndView importFile(
      @RequestParam("file") MultipartFile multipartFile, Authentication authentication)
      throws IOException {
    var username = authentication.getName();
    if (multipartFile == null
        || multipartFile.isEmpty()
        || !StringUtils.hasText(multipartFile.getOriginalFilename())) {
      log.debug("No file selected for upload by {}", username);
      return new ModelAndView(
          new RedirectView("files", true),
          new ModelMap().addAttribute("uploadSuccess", NOTHING_TO_UPLOAD));
    }

    var originalFilename = multipartFile.getOriginalFilename();
    if (!isSafeFilename(originalFilename) || !isSafePathComponent(username)) {
      log.warn("Rejected upload with path component from {}", username);
      return uploadRejected();
    }

    try {
      Path configuredRoot = Path.of(fileLocation).toAbsolutePath().normalize();
      Files.createDirectories(configuredRoot);
      Path realRoot = configuredRoot.toRealPath();
      Path destinationDir = realRoot.resolve(username).normalize();
      if (!realRoot.equals(destinationDir.getParent())) {
        return uploadRejected();
      }
      Files.createDirectories(destinationDir);
      Path realDestinationDir = destinationDir.toRealPath();
      if (!realRoot.equals(realDestinationDir.getParent())) {
        return uploadRejected();
      }

      Path destinationFile = realDestinationDir.resolve(originalFilename).normalize();
      if (!destinationFile.startsWith(realDestinationDir)
          || !realDestinationDir.equals(destinationFile.getParent())
          || Files.isSymbolicLink(destinationFile)) {
        return uploadRejected();
      }

      try (InputStream is = multipartFile.getInputStream();
          var output =
              Files.newOutputStream(
                  destinationFile,
                  StandardOpenOption.CREATE,
                  StandardOpenOption.TRUNCATE_EXISTING,
                  StandardOpenOption.WRITE,
                  LinkOption.NOFOLLOW_LINKS)) {
        is.transferTo(output);
      }
      log.debug("File saved to {}", destinationFile);
    } catch (IOException | InvalidPathException e) {
      log.warn("Unable to store uploaded file for {}", username, e);
      return uploadRejected();
    }

    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", UPLOAD_SUCCESSFUL));
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

  private static boolean isSafeFilename(String filename) {
    return isSafePathComponent(filename)
        && !ENCODED_PATH_CHARACTER.matcher(filename).find()
        && filename.indexOf(':') < 0
        && !filename.endsWith(".")
        && !filename.endsWith(" ")
        && !filename.matches("(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?$");
  }

  private static ModelAndView uploadRejected() {
    return new ModelAndView(
        new RedirectView("files", true),
        new ModelMap().addAttribute("uploadSuccess", NOTHING_TO_UPLOAD));
  }

  @GetMapping(value = "/files")
  public ModelAndView getFiles(
      HttpServletRequest request, Authentication authentication, TimeZone timezone) {
    String username = (null != authentication) ? authentication.getName() : "anonymous";
    File destinationDir = new File(fileLocation, username);

    ModelAndView modelAndView = new ModelAndView();
    modelAndView.setViewName("files");
    // the message of the upload we are redirected from, see importFile and
    // FileUploadExceptionAdvice
    var uploadMessage = request.getParameter("uploadSuccess");
    if (StringUtils.hasText(uploadMessage)) {
      modelAndView.addObject("uploadSuccess", uploadMessage);
      modelAndView.addObject("uploadFailed", !UPLOAD_SUCCESSFUL.equals(uploadMessage));
    }

    record UploadedFile(String name, String size, String link, String creationTime) {}

    var uploadedFiles = new ArrayList<UploadedFile>();
    File[] files = destinationDir.listFiles(File::isFile);
    if (files != null) {
      for (File file : files) {
        String size = FileUtils.byteCountToDisplaySize(file.length());
        String link = String.format("files/%s/%s", username, file.getName());
        uploadedFiles.add(
            new UploadedFile(file.getName(), size, link, getCreationTime(timezone, file)));
      }
    }

    modelAndView.addObject(
        "files",
        uploadedFiles.stream().sorted(comparing(UploadedFile::creationTime).reversed()).toList());
    modelAndView.addObject("webwolf_url", "http://" + server + ":" + port + contextPath);
    return modelAndView;
  }

  private String getCreationTime(TimeZone timezone, File file) {
    try {
      FileTime creationTime = (FileTime) Files.getAttribute(file.toPath(), "creationTime");
      ZonedDateTime zonedDateTime = creationTime.toInstant().atZone(timezone.toZoneId());
      return dateTimeFormatter.format(zonedDateTime);
    } catch (IOException e) {
      return "unknown";
    }
  }
}
