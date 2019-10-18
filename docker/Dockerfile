FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH iparse.IPArse

# Switch to assemblyline user
USER assemblyline

# Copy IPArse service code
WORKDIR /opt/al_service
COPY . .

