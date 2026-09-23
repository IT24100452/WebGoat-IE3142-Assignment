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
