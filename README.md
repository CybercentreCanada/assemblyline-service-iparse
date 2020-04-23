# IPArse Service

Extracts information from IPA package files.

##### Result Output

1.  Identifies bundle's main executable file.
2.  Lists all PLIST file data and will identify known keys (listed in keys.json file) and unknown keys

    Tagged values in result:
    
    - file.plist.installer_url
    - file.plist.build.machine_os
    - file.plist.cf_bundle.development_region
    - file.plist.cf_bundle.display_name
    - file.plist.cf_bundle.executable
    - file.plist.cf_bundle.identifier
    - file.plist.cf_bundle.name
    - file.plist.cf_bundle.pkg_type
    - file.plist.cf_bundle.version.short
    - file.plist.cf_bundle.signature
    - file.plist.cf_bundle.url_scheme
    - file.plist.cf_bundle.version.long
    - file.plist.dt.compiler
    - file.plist.dt.platform.build
    - file.plist.dt.platform.name
    - file.plist.dt.platform.version
    - file.plist.ls.background_only
    - file.plist.ls.min_system_version
    - file.plist.min_os_version
    - file.plist.ns.apple_script_enabled
    - file.plist.ns.principal_class
    - file.plist.request_open_access
    - file.plist.ui.background_modes
    - file.plist.ui.requires_persistent_wifi
    - file.plist.wk.app_bundle_identifier

3.  Will display information in PkgInfo file

4.  Flags files of potential interest, for example certificate and plist files.

5.  Detects IOC patterns using FrankenStrings Patterns module.

##### Extracted Files

This service does not extract the archived content as the AL Extract service will handle this function
