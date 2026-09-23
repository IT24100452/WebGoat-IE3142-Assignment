# WebGoat Docker Image - IE3142 Assignment
# This image runs the WebGoat application in a container

# Start from the official Eclipse Temurin JDK 25 image
# This includes Java 25 and a minimal Linux environment
FROM docker.io/eclipse-temurin:25-jdk-noble

LABEL name="WebGoat: A deliberately insecure Web Application"
LABEL maintainer="WebGoat team"

# Install essential tools and prepare the application user
RUN \
  # Update package lists
  apt-get update && \
  # Install curl (needed for health checks)
  apt-get install -y --no-install-recommends curl && \
  # Remove package lists to reduce image size
  rm -rf /var/lib/apt/lists/* && \
  # Create a non-root user 'webgoat' for security (containers should not run as root)
  useradd -ms /bin/bash webgoat && \
  # Create the WebGoat data directory
  mkdir -p /home/webgoat/.webgoat-2026.2-SNAPSHOT && \
  # Allow group members to access the home directory (for better container security)
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat && \
  # Ensure the data directory is writable
  chmod 777 /home/webgoat/.webgoat-2026.2-SNAPSHOT

# Switch to the non-root 'webgoat' user for all subsequent commands
USER webgoat

# Copy the compiled JAR file from the build context into the image
COPY --chown=webgoat target/webgoat-*.jar /home/webgoat/webgoat.jar

# Expose the two ports where WebGoat and WebWolf listen
# Note: docker-compose.yml binds these only to localhost
EXPOSE 8080
EXPOSE 9090

# Set the container timezone
ENV TZ=Europe/Amsterdam

# Set the working directory where Java will run
WORKDIR /home/webgoat

# Run the WebGoat application with special JVM flags for compatibility
# The --add-opens flags allow lessons that need to access internal Java classes
ENTRYPOINT [ "java", \
   "-Duser.home=/home/webgoat", \
   "-Dfile.encoding=UTF-8", \
   "--add-opens", "java.base/java.lang=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED", \
   "--add-opens", "java.base/java.text=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.beans=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.awt.font=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "-Drunning.in.docker=true", \
   "-jar", "webgoat.jar", \
   # Bind to all addresses inside the container (0.0.0.0)
   # The actual external access is restricted by docker-compose.yml
   "--server.address", "0.0.0.0" ]

# Docker health check: verify the application responds to requests
HEALTHCHECK --interval=5s --timeout=3s \
  CMD curl --fail http://localhost:8080/WebGoat/actuator/health || exit 1
