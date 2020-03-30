FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH iparse.iparse.IPArse

USER root

RUN apt-get update && apt-get install -y p7zip-full && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

RUN pip install --no-cache-dir --user biplist && rm -rf ~/.cache/pip

# Copy IPArse service code
WORKDIR /opt/al_service
COPY . .
