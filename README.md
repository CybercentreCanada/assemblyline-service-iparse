[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_iparse-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-iparse)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-iparse)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-iparse)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-iparse)](./LICENSE)

# IPArse Service

This service extracts information from IPA package files.

## Service Details

The service will output the following information, if available:

1.  Identifies bundle's main executable file.
2.  Lists all PLIST file data and will identify known keys (listed in keys.json file) and unknown keys

    Tagged values in result:

    - `file.plist.installer_url`
    - `file.plist.build.machine_os`
    - `file.plist.cf_bundle.development_region`
    - `file.plist.cf_bundle.display_name`
    - `file.plist.cf_bundle.executable`
    - `file.plist.cf_bundle.identifier`
    - `file.plist.cf_bundle.name`
    - `file.plist.cf_bundle.pkg_type`
    - `file.plist.cf_bundle.version.short`
    - `file.plist.cf_bundle.signature`
    - `file.plist.cf_bundle.url_scheme`
    - `file.plist.cf_bundle.version.long`
    - `file.plist.dt.compiler`
    - `file.plist.dt.platform.build`
    - `file.plist.dt.platform.name`
    - `file.plist.dt.platform.version`
    - `file.plist.ls.background_only`
    - `file.plist.ls.min_system_version`
    - `file.plist.min_os_version`
    - `file.plist.ns.apple_script_enabled`
    - `file.plist.ns.principal_class`
    - `file.plist.request_open_access`
    - `file.plist.ui.background_modes`
    - `file.plist.ui.requires_persistent_wifi`
    - `file.plist.wk.app_bundle_identifier`

3.  Will display information in PkgInfo file

4.  Flags files of potential interest, for example certificate and plist files.

5.  Detects IOC patterns using FrankenStrings Patterns module.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Iparse \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-iparse

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service IPArse

Ce service extrait des informations des fichiers de paquets IPA.

## Détails du service

Le service fournira les informations suivantes, si elles sont disponibles :

1.  Identifie le fichier exécutable principal de l'offre groupée.
2.  Liste toutes les données du fichier PLIST et identifie les clés connues (listées dans le fichier keys.json) et les clés inconnues.

    Valeurs étiquetées dans le résultat :

    - `file.plist.installer_url`
    - `file.plist.build.machine_os`
    - `file.plist.cf_bundle.development_region`
    - `file.plist.cf_bundle.display_name`
    - `file.plist.cf_bundle.executable`
    - `file.plist.cf_bundle.identifier`
    - `file.plist.cf_bundle.name` (fichier.plist.cf_bundle.nom)
    - `file.plist.cf_bundle.pkg_type`
    - `file.plist.cf_bundle.version.short`
    - `file.plist.cf_bundle.signature`
    - `file.plist.cf_bundle.url_scheme`
    - `file.plist.cf_bundle.version.long`
    - `file.plist.dt.compiler`
    - `file.plist.dt.platform.build` (fichier.plist.dt.plateforme.construction)
    - `file.plist.dt.platform.name`
    - `file.plist.dt.platform.version`
    - `file.plist.ls.background_only`
    - `file.plist.ls.min_system_version`
    - `file.plist.min_os_version`
    - `file.plist.ns.apple_script_enabled`
    - `file.plist.ns.principal_class`
    - `file.plist.request_open_access`
    - `file.plist.ui.background_modes`
    - `file.plist.ui.requires_persistent_wifi`
    - `file.plist.wk.app_bundle_identifier`

3.  Affiche les informations dans le fichier PkgInfo

4.  Signale les fichiers d'intérêt potentiel, par exemple les certificats et les fichiers plist.

5.  Détecte les modèles IOC à l'aide du module FrankenStrings Patterns.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Iparse \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-iparse

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
