from assemblyline.al.service.base import ServiceBase
from assemblyline.common.charset import safe_str
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT

class IPArse(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'archive/zip'
    SERVICE_DESCRIPTION = "IPA File Analyzer"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 150
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 0.5
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(IPArse, self).__init__(cfg)

    def start(self):
        self.log.debug("iParse service started")

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global biplist, json, os, plistlib, re, subprocess, unicodedata, zipfile
        import biplist
        import os
        import json
        import plistlib
        import re
        import subprocess
        import unicodedata
        import zipfile

    def isipa(self, zf):
        # Help from https://herkuang.info/en/2016/01/22/extract-app-info-in-ipa-files-using-python/
        name_list = zf.namelist()
        # Look for info.plist
        pattern = re.compile(r'Payload/[^/]*.app/Info.plist')
        for p in name_list:
            m = pattern.match(p)
            if m is not None:
                return name_list, m.group()
        return name_list, False

    def extract_archive(self, zf):
        p = subprocess.Popen(["7z", "x", zf, "-o{}" .format(self.working_directory)], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        stdout, stderr = p.communicate()
        if stderr:
            raise Exception(stderr)
        return

    def execute(self, request):
        result = Result()
        request.result = result
        wrk_dir = self.working_directory
        ipa_path = request.download()

        # Determine if PK container has IPA content to parse
        try:
            ipa_file = zipfile.ZipFile(ipa_path)
        except zipfile.BadZipfile:
            # Return if files cannot be extracted
            return
        name_list, isipa = self.isipa(ipa_file)

        if not isipa:
            return

        # Info.plist
        with open(os.path.join(os.path.dirname(__file__), "keys.json"), 'r') as f:
            keys_dict = json.load(f)

        infoplist_common = keys_dict['glossary']
        info_plist = ipa_file.read(isipa)

        try:
            plist_parsed = plistlib.readPlistFromString(info_plist)
        except:
            try:
                plist_parsed = biplist.readPlistFromString(info_plist)
            except Exception as e:
                self.log.info("Not a plist:", e)
                return

        res = ResultSection(SCORE.NULL, "Info.plist")
        known = []
        unknown = []
        main_exe = ""
        for k, i in plist_parsed.iteritems():
            k_noipad = k.replace("~ipad", "")
            # Grab the main executable name
            if k == "CFBundleExecutable":
                try:
                    main_exe = (i, "Name of bundle's main executable file: {}" .format(i))
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    main_exe = (i, "Name of bundle's main executable file: {}".format(i))
            elif k_noipad in infoplist_common:
                try:
                    known.append("{} ({}):  {}".format(k, infoplist_common[k_noipad][0], i))
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    known.append("{} ({}):  {}".format(k, infoplist_common[k_noipad][0], i))
            else:
                try:
                    unknown.append("{}:  {}".format(k, i))
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    unknown.append("{}:  {}".format(k, i))
                continue
            if infoplist_common[k_noipad][1]:
                if isinstance(i, list):
                    for val in i:
                        res.add_tag(TAG_TYPE["PLIST_{}".format(k_noipad.upper())], val, TAG_WEIGHT.LOW)
                else:
                    res.add_tag(TAG_TYPE["PLIST_{}".format(k_noipad.upper())], i, TAG_WEIGHT.LOW)

        if main_exe != "":
            res.add_line(main_exe[1])
        if len(known) > 0:
            idenkey_sec = ResultSection(SCORE.NULL, "Identified Keys", parent=res)
            for r in sorted(known):
                idenkey_sec.add_line(r)

        if len(unknown) > 0:
            unkkey_sec = ResultSection(SCORE.NULL, "UNIDENTIFIED KEYS:", parent=res)
            unkkey_sec.add_line("Go to https://developer.apple.com/library/content/documentation/General/Reference"
                                "/InfoPlistKeyReference/Introduction/Introduction.html")
            for r in sorted(unknown):
                unkkey_sec.add_line(r)

        result.add_section(res)

        # PkgInfo file
        pkg_types = {
            'APPL': 'application',
            'FMWK': 'frameworks',
            'BNDL': 'loadable bundle'
        }
        pattern = re.compile(r'Payload/[^/]*.app/PkgInfo')
        for fn in name_list:
            m = pattern.match(fn)
            if m is not None:
                pkg_info = ipa_file.read(m.group())
                if len(pkg_info) == 8:
                    try:
                        pkgtype = pkg_info[0:4]
                        if pkgtype in pkg_types:
                            pkgtype = pkg_types[pkgtype]
                        creator_code = pkg_info[4:]
                        res = ResultSection(SCORE.NULL, "PkgInfo Details")
                        res.add_line("Package Type: {}; Application Signature: {}".format(pkgtype, creator_code))
                        result.add_section(res)
                    except Exception:
                        continue

        # Extract Files of interest using 7zip (some files can be AES encrypted which standard zipfile library does not
        # support)
        extract_success = False
        try:
            self.extract_archive(ipa_path)
            extract_success = True
        except Exception as e:
            self.log.error("Could not extract IPA file due to 7zip error {}" .format(e))

        if not extract_success:
            return

        fextract_regs = [
            (r'.*{}$' .format(main_exe[0]), "Main executable file {}" .format(main_exe[0])),
            (r'.*\.(?:crt|cer|der|key|p12|p7b|p7c|pem|pfx)$', "Certificate or key file"),
            (r'.*libswift[^\/]\.dylib$', "Swift code library files"),
            (r'META-INF\/.*ZipMetadata.plist$', "IPA archive content info"),
            (r'.*mobileprovision$', "Provisioning profile for limiting app uploads"),
            (r'.*plist$', "Plist information file"),
        ]

        int_files = {}
        for root, dirs, files in os.walk(os.path.join(wrk_dir, "Payload")):
                for name in files:
                    matched = False
                    full_path = safe_str(os.path.join(root, name))
                    if os.path.getsize(full_path) < 50000001:
                        for p, desc in fextract_regs:
                            pattern = re.compile(p)
                            m = pattern.match(full_path.decode("utf8"))
                            if m is not None:
                                if not desc.startswith("Main executable file "):
                                    if int_files.get(desc, None):
                                        int_files[desc].append(full_path)
                                    else:
                                        int_files[desc] = []
                                        int_files[desc].append(full_path)
                                request.add_extracted(full_path, desc)
                                matched = True
                                break
                        # Extract all files under 5MB
                        if not matched:
                            request.add_extracted(full_path, "Extracted file")

        if len(int_files) > 0:
            intf_sec = ResultSection(SCORE.NULL, "Files of interest", parent=res)
            for intf_d, intf_p in int_files.iteritems():
                intf_subsec = ResultSection(SCORE.NULL, intf_d, parent=intf_sec)
                for f in intf_p:
                    intf_subsec.add_line(f.replace("{}/" .format(wrk_dir), ""))


