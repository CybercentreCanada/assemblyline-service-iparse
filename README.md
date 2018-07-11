# IPArse Static Service

Extracts information from IPA package files.

### Information Extracted 
##### Result Output
1.  Identifies bundle's main executable file.
2.  Lists all PLIST file data and will identify known keys (listed in keys.json file) and unknown keys

    Tagged values in result:
    
    - APINSTALLERURL
    - BUILDMACHINEOSBUILD
    - CFBUNDLEDEVELOPMENTREGION
    - CFBUNDLEDISPLAYNAME
    - CFBUNDLEEXECUTABLE
    - CFBUNDLEIDENTIFIER
    - CFBUNDLENAME
    - CFBUNDLEPACKAGETYPE
    - CFBUNDLESHORTVERSIONSTRING
    - CFBUNDLESIGNATURE
    - CFBUNDLEURLSCHEMES
    - CFBUNDLEVERSION
    - DTCOMPILER
    - DTPLATFORMBUILD
    - DTPLATFORMNAME
    - DTPLATFORMVERSION
    - LSBACKGROUNDONLY
    - LSMINIMUMSYSTEMVERSION
    - MINIMUMOSVERSION
    - NSAPPLESCRIPTENABLED
    - NSPRINCIPALCLASS
    - REQUESTSOPENACCESS
    - UIBACKGROUNDMODES
    - UIREQUIRESPERSISTENTWIFI
    - WKAPPBUNDLEIDENITIFE

3.  Will display information in PkgInfo file

4.  Flags files of potential interest, for example certificate and plist files.

##### Extracted Files

This service does not extract the archived content as the AL Extract service will handle this function
