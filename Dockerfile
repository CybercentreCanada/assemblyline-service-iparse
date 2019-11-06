FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH iparse.iparse.IPArse

RUN apt-get update && apt-get install -y \
  p7zip-full

RUN pip install \
  biplist

# Switch to assemblyline user
USER assemblyline

# Copy IPArse service code
WORKDIR /opt/al_service
COPY . .
