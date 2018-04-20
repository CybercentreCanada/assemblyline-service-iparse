# IPArse Static Service

Note: Currently this service is in the first stages of development and therefore this README may not be entirely accurate.

Extracts information from IPA package files.

### Information Extracted 
##### Result Output
1.  Identifies bundle's main executable file.
2.  Lists Info.plist data and will identify known keys (listed in keys.json file) and unknown keys

    Tagged values in result:
    
    -   APINSTALLERURL
    -   BUILDMACHINEOSBUILD
    -   CFBUNDLEDEVELOPMENTREGION
    -   CFBUNDLEDISPLAYNAME
    -   CFBUNDLEIDENTIFIER
    -   CFBUNDLENAME
    -   CFBUNDLEPACKAGETYPE
    -   CFBUNDLESHORTVERSIONSTRING
    -   CFBUNDLESIGNATURE
    -   CFBUNDLEURLSCHEMES
    -   CFBUNDLEVERSION
    -   DTCOMPILER
    -   DTPLATFORMBUILD
    -   DTPLATFORMNAME
    -   DTPLATFORMVERSION
    -   LSBACKGROUNDONLY
    -   LSMINIMUMSYSTEMVERSION
    -   NSAPPLESCRIPTENABLED
    -   NSPRINCIPALCLASS
    -   REQUESTSOPENACCESS
    -   UIBACKGROUNDMODES
    -   UIREQUIRESPERSISTENTWIFI
    -   WKAPPBUNDLEIDENITIFER

3.  Will display information in PkgInfo file

4.  Flags files of potential interest, for example certificate and plist files.

##### Extracted Files

Will extract any file in the container <= 5MB
