from assemblyline.al.service.base import ServiceBase
from assemblyline.common.charset import safe_str
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT

class IPArse(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = 'archive/zip'
    SERVICE_DESCRIPTION = "IPA File Analyzer"
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_TIMEOUT = 60
    SERVICE_ENABLED = True
    SERVICE_CPU_CORES = 0.1
    SERVICE_RAM_MB = 256

    def __init__(self, cfg=None):
        super(IPArse, self).__init__(cfg)
        self.result = None
        self.known_keys = None
        self.reported_keys = None

    def start(self):
        self.log.debug("iParse service started")

    # noinspection PyUnresolvedReferences,PyGlobalUndefined
    def import_service_deps(self):
        global biplist, json, os, PatternMatch, plistlib, re, subprocess, unicodedata, zipfile
        import biplist
        import os
        import json
        import plistlib
        import re
        import subprocess
        import unicodedata
        import zipfile
        try:
            from al_services.alsvc_frankenstrings.balbuzard.patterns import PatternMatch
        except ImportError:
            PatternMatch = None

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

    def extract_iocs(self, val, patterns):
        st_value = patterns.ioc_match(val, bogon_ip=True)
        if len(st_value) > 0:
            for ty, val in st_value.iteritems():
                if val == "":
                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                    self.result.add_tag(TAG_TYPE[ty], asc_asc, TAG_WEIGHT.LOW)
                else:
                    ulis = list(set(val))
                    for v in ulis:
                        self.result.add_tag(TAG_TYPE[ty], v, TAG_WEIGHT.LOW)
        return

    def gen_plist_extract(self, plistfile, patterns):
        # Get PLIST dictionary
        empty = None
        plist_dict = None
        with open(plistfile, 'r') as f:
            info_plist = f.read()

        if info_plist == "":
            empty = True
            return empty, plist_dict
        else:
            try:
                plist_dict = plistlib.readPlistFromString(info_plist)
            except:
                try:
                    plist_dict = biplist.readPlistFromString(info_plist)
                except Exception as e:
                    return empty, plist_dict

        # Find IOCs in plist
        if patterns and plist_dict:
            plist_str = json.dumps(plist_dict, default=str)
            self.extract_iocs(plist_str, patterns)

        return empty, plist_dict

    def parse_plist(self, pdict):

        idenkey_sec = None
        unkkey_sec = None

        known = set()
        unknown = set()

        for k, i in pdict.iteritems():
            k_noipad = k.replace("~ipad", "")
            # Many plist files are duplicates of info.plist, do not report on keys already identified
            if k_noipad in self.reported_keys:
                if i in self.reported_keys[k_noipad]:
                    continue
                self.reported_keys[k_noipad].append(i)
            else:
                self.reported_keys[k_noipad] = [i]
            if k_noipad in self.known_keys:
                try:
                    known.add("{} ({}):  {}".format(k, self.known_keys[k_noipad][0], i))
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    known.add("{} ({}):  {}".format(k, self.known_keys[k_noipad][0], i))
            else:
                try:
                    unknown.add("{}:  {}".format(k, i))
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    unknown.add("{}:  {}".format(k, i))
                continue
            if self.known_keys[k_noipad][1]:
                if isinstance(i, list):
                    for val in i:
                        self.result.add_tag(TAG_TYPE["PLIST_{}".format(k_noipad.upper())], val, TAG_WEIGHT.LOW)
                else:
                    self.result.add_tag(TAG_TYPE["PLIST_{}".format(k_noipad.upper())], i, TAG_WEIGHT.LOW)

        if len(known) > 0:
            idenkey_sec = ResultSection(SCORE.NULL, "Identified Keys")
            for r in sorted(known):
                idenkey_sec.add_line(r)

        if len(unknown) > 0:
            unkkey_sec = ResultSection(SCORE.NULL, "UNIDENTIFIED KEYS:")
            for r in sorted(unknown):
                unkkey_sec.add_line(r)

        return idenkey_sec, unkkey_sec

    def execute(self, request):
        self.result = Result()
        request.result = self.result
        wrk_dir = self.working_directory
        ipa_path = request.download()
        self.known_keys = None
        self.reported_keys = {}

        # Determine if PK container has IPA content to parse
        try:
            ipa_file = zipfile.ZipFile(ipa_path)
        except zipfile.BadZipfile:
            # Return if files cannot be extracted
            return
        # isipa returns False if Info.plist not found, or returns Info.plist path
        name_list, isipa = self.isipa(ipa_file)

        if not isipa:
            return

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

        with open(os.path.join(os.path.dirname(__file__), "keys.json"), 'r') as f:
            keys_dict = json.load(f)
            self.known_keys = keys_dict['glossary']

        patterns = None
        if PatternMatch:
            patterns = PatternMatch()

        # Info.plist
        main_exe = None
        res = ResultSection(SCORE.NULL, "Info.plist")
        info_plist_path = os.path.join(wrk_dir, isipa)

        isempty, plist_dict = self.gen_plist_extract(info_plist_path, patterns)

        if plist_dict is None:
            res.add_line("Info.plist in sample cannot be parsed. Sample may not corrupt.")

        elif isempty:
            res.add_line("Empty Info.plist file. Archive contents may be encrypted.")

        else:
            # Grab the main executable name
            if plist_dict.get("CFBundleExecutable", None):
                i = plist_dict["CFBundleExecutable"]
                try:
                    main_exe = (i, "Name of bundle's main executable file: {}".format(i))
                    res.add_line(main_exe[1])
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    main_exe = (i, "Name of bundle's main executable file: {}".format(i))
                    res.add_line(main_exe[1])

            iden_key_res, unk_key_res = self.parse_plist(plist_dict)
            if iden_key_res:
                res.add_section(iden_key_res)
            if unk_key_res:
                res.add_section(unk_key_res)
            self.result.add_section(res)

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
                res = ResultSection(SCORE.NULL, "PkgInfo Details")
                pkg_info_path = os.path.join(wrk_dir, m.group())
                with open(pkg_info_path, 'r') as f:
                    pkg_info = f.read()
                if pkg_info == "":
                    res.add_line("Empty PkgInfo file. Archive contents may be encrypted.")
                elif len(pkg_info) == 8:
                    try:
                        pkgtype = pkg_info[0:4]
                        if pkgtype in pkg_types:
                            pkgtype = pkg_types[pkgtype]
                        creator_code = pkg_info[4:]
                        res = ResultSection(SCORE.NULL, "PkgInfo Details")
                        res.add_line("Package Type: {}; Application Signature: {}".format(pkgtype, creator_code))
                    except Exception:
                        continue
                self.result.add_section(res)

        if main_exe:
            main_exe_reg = (r'.*{}$' .format(main_exe[0]), "Main executable file {}" .format(main_exe[0]))
        else:
            main_exe_reg = ('$', 'Place holder for missing main executable name.')

        fextract_regs = [
            main_exe_reg,
            (r'Payload.*\.(?:crt|cer|der|key|p12|p7b|p7c|pem|pfx)$', "Certificate or key file"),
            (r'Payload.*libswift[^\/]\.dylib$', "Swift code library files"),
            (r'Payload\/META-INF\/.*ZipMetadata.plist$', "IPA archive content info"),
            (r'Payload.*mobileprovision$', "Provisioning profile for limiting app uploads"),
            (r'.*plist$', "Plist information file"),
        ]

        empty_file_msg = "Empty file. Archive contents may be encrypted."
        int_files = {}
        plist_res = ResultSection(SCORE.NULL, "Other Plist File Information (displaying new key-value pairs only)")
        for root, dirs, files in os.walk(wrk_dir):
                for name in files:
                    full_path = safe_str(os.path.join(root, name))
                    if os.path.getsize(full_path) == 0:
                        if int_files.get(empty_file_msg, None):
                            int_files[empty_file_msg].append(full_path)
                        else:
                            int_files[empty_file_msg] = []
                            int_files[empty_file_msg].append(full_path)
                    else:
                        for p, desc in fextract_regs:
                            pattern = re.compile(p)
                            m = pattern.match(full_path.decode("utf8"))
                            if m is not None:
                                # Already identify main executable file above
                                if not desc.startswith("Main executable file "):
                                    if desc.startswith("Plist"):
                                        pres = ResultSection(SCORE.NULL, "{}" .format(full_path.replace(wrk_dir, "")))
                                        isempty, plist_parsed = self.gen_plist_extract(full_path, patterns)
                                        if not isempty and plist_parsed:
                                            iden_key_res, unk_key_res = self.parse_plist(plist_dict)
                                            if iden_key_res:
                                                pres.add_section(iden_key_res)
                                            if unk_key_res:
                                                pres.add_section(unk_key_res)
                                            plist_res.add_section(pres)
                                    elif int_files.get(desc, None):
                                        int_files[desc].append(full_path)
                                    else:
                                        int_files[desc] = []
                                        int_files[desc].append(full_path)
                                break

        if len(plist_res.subsections) > 0:
            self.result.add_section(plist_res)

        if len(int_files) > 0:
            intf_sec = ResultSection(SCORE.NULL, "Files of interest", parent=res)
            for intf_d, intf_p in int_files.iteritems():
                intf_subsec = ResultSection(SCORE.NULL, intf_d, parent=intf_sec)
                for f in intf_p:
                    intf_subsec.add_line(f.replace("{}/" .format(wrk_dir), ""))


