ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH iparse.iparse.IPArse

USER root

RUN apt-get update && apt-get install -y p7zip-full && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy IPArse service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
