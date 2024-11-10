# Use the official PostgreSQL image as the base
FROM postgres:latest

# Set environment variables for the default PostgreSQL user and password
ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

# Copy the initialization script into the container
COPY init-databases.sql /docker-entrypoint-initdb.d/

# Expose PostgreSQL port
EXPOSE 5432