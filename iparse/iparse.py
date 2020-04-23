import json
import os
import plistlib
import re
import unicodedata
import zipfile
from collections import defaultdict
from subprocess import Popen, PIPE

import biplist

from assemblyline.common.str_utils import safe_str
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection

TAG_MAP = {
    "APINSTALLERURL": "file.plist.installer_url",
    "BUILDMACHINEOSBUILD": "file.plist.build.machine_os",
    "CFBUNDLEDEVELOPMENTREGION": "file.plist.cf_bundle.development_region",
    "CFBUNDLEDISPLAYNAME": "file.plist.cf_bundle.display_name",
    "CFBUNDLEEXECUTABLE": "file.plist.cf_bundle.executable",
    "CFBUNDLEIDENTIFIER": "file.plist.cf_bundle.identifier",
    "CFBUNDLENAME": "file.plist.cf_bundle.name",
    "CFBUNDLEPACKAGETYPE": "file.plist.cf_bundle.pkg_type",
    "CFBUNDLESIGNATURE": "file.plist.cf_bundle.signature",
    "CFBUNDLEURLSCHEMES": "file.plist.cf_bundle.url_scheme",
    "CFBUNDLEVERSION": "file.plist.cf_bundle.version.long",
    "CFBUNDLESHORTVERSIONSTRING": "file.plist.cf_bundle.version.short",
    "DTCOMPILER": "file.plist.dt.compiler",
    "DTPLATFORMBUILD": "file.plist.dt.platform.build",
    "DTPLATFORMNAME": "file.plist.dt.platform.name",
    "DTPLATFORMVERSION": "file.plist.dt.platform.version",
    "LSBACKGROUNDONLY": "file.plist.ls.background_only",
    "LSMINIMUMSYSTEMVERSION": "file.plist.ls.min_system_version",
    "MINIMUMOSVERSION": "file.plist.min_os_version",
    "NSAPPLESCRIPTENABLED": "file.plist.ns.apple_script_enabled",
    "NSPRINCIPALCLASS": "file.plist.ns.principal_class",
    "REQUESTSOPENACCESS": "file.plist.requests_open_access",
    "UIBACKGROUNDMODES": "file.plist.ui.background_modes",
    "UIREQUIRESPERSISTENTWIFI": "file.plist.ui.requires_persistent_wifi",
    "WKAPPBUNDLEIDENITIFER": "file.plist.wk.app_bundle_identifier",
}


class IPArse(ServiceBase):

    def __init__(self, config=None):
        super(IPArse, self).__init__(config)
        self.result = None
        self.known_keys = None
        self.reported_keys = None

    def start(self):
        self.log.debug("IPArse service started")

    @staticmethod
    def isipa(zf):
        """Determines if sample is an IPA file.

        Args:
            zf: Archived file path.

        Returns:
            List of file names contained in archive and boolean value if sample is an IPA file.
        """
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
        """Extracts an archive file type to the file system.

        Args:
            zf: Archived file path.

        Returns:
            None.
        """

        stdout, stderr = Popen(['7z', 'x', zf, f"-o{self.working_directory}"], stdout=PIPE, stderr=PIPE).communicate()

        if stderr:
            raise Exception(stderr)
        return

    def extract_iocs(self, val, patterns):
        """Finds IOC patterns and reports as an AL tag in result.

        Args:
            val: Value to be checked.
            patterns: FrankenStrings Patterns() object.

        Returns:
            None.
        """
        st_value = patterns.ioc_match(val, bogon_ip=True)
        if len(st_value) > 0:
            for ty, val in list(st_value.items()):
                if val == "":
                    asc_asc = unicodedata.normalize('NFKC', val).encode('ascii', 'ignore')
                    self.result.add_tag(ty, asc_asc)
                else:
                    ulis = list(set(val))
                    for v in ulis:
                        self.result.add_tag(ty, v)
        return

    def gen_plist_extract(self, plistfile, patterns):
        """Open plist file object and extract info.

        Args:
            plistfile: Plist item of type LIST.
            patterns: FrankenStrings Patterns() object.

        Returns:
            True if plist file is not empty and dictionary/list object containing plist information if present.
        """
        # Get PLIST dictionary
        empty = None
        plist_dict = None
        with open(plistfile, 'rb') as f:
            info_plist = f.read()

        if info_plist == "":
            empty = True
            return empty, plist_dict
        else:
            # noinspection PyBroadException
            try:
                plist_dict = plistlib.loads(info_plist)
            except Exception:
                # noinspection PyBroadException
                try:
                    plist_dict = biplist.readPlistFromString(info_plist)
                except Exception:
                    empty = True
                    return empty, plist_dict

        # Find IOCs in plist
        if patterns and plist_dict:
            # noinspection PyBroadException
            try:
                plist_str = json.dumps(plist_dict, default=str)
                self.extract_iocs(plist_str, patterns)
            except Exception:
                pass
        return empty, plist_dict

    @staticmethod
    def transform_dicts(orig_dict):
        """Transforms a plist object that is type LIST to type DICT.

        Args:
            orig_dict: Plist item of type LIST.

        Returns:
            Transformed plist item.
        """
        dfli = defaultdict(list)
        for x in orig_dict:
            # If item is a dictionary, expand and add values
            if isinstance(x, dict):
                for k, v in list(x.items()):
                    dfli[str(safe_str(k))].append(str(safe_str(v)))
            else:
                dfli.setdefault(str(safe_str(x)))

        merged = dict(dfli)

        return merged

    def parse_plist(self, pdict):
        """Attempts to extract and identify all known and unknown keys of a plist file.

        Args:
            pdict: Plist dictionary item.

        Returns:
            A list of known keys and a list of unknown keys.
        """

        idenkey_sec = ResultSection("Identified Keys")
        unkkey_sec = ResultSection("Unidentified Keys:")

        # Sometimes plist is a list of dictionaries, or it is just a list. Will merge dict /convert to dict for now
        if isinstance(pdict, list):
            pdict = self.transform_dicts(pdict)

        for k, i in list(pdict.items()):
            # Prepare Keys
            k = str(safe_str(k))
            k_noipad = k.replace("~ipad", "")

            # Prepare values
            if i is None:
                i = [""]
            elif not isinstance(i, list):
                i = [i]

            # Many plist files are duplicates of info.plist, do not report on keys already identified
            if k_noipad in self.reported_keys:
                if i in self.reported_keys[k_noipad]:
                    continue
                self.reported_keys[k_noipad].append(i)
            else:
                self.reported_keys[k_noipad] = [i]

            # Process known keys
            if k_noipad in self.known_keys:
                desc, create_tag = self.known_keys[k_noipad]

                idenkey_sec.add_line(f"{k} ({desc}): {', '.join([safe_str(x, force_str=True) for x in i])}")
                if create_tag:
                    for val in i:
                        idenkey_sec.add_tag(TAG_MAP[k_noipad.upper()], safe_str(val, force_str=True))

            else:
                unkkey_sec.add_line(f"{k}: {', '.join([safe_str(x, force_str=True) for x in i])}")

        if idenkey_sec.body is None:
            idenkey_sec = None

        if unkkey_sec.body is None:
            unkkey_sec = None

        return idenkey_sec, unkkey_sec

    def execute(self, request):
        """Main Module. See README for details."""
        request.result = Result()
        self.result = request.result
        wrk_dir = self.working_directory
        ipa_path = request.file_path
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
            self.log.error(f"Could not extract IPA file due to 7zip error {e}")

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
        res = ResultSection("Info.plist")
        info_plist_path = os.path.join(wrk_dir, isipa)

        isempty, plist_dict = self.gen_plist_extract(info_plist_path, patterns)

        if plist_dict is None:
            res.add_line("Info.plist in sample cannot be parsed. Sample may be corrupt.")

        elif isempty:
            res.add_line("Empty Info.plist file. Archive contents may be encrypted.")

        else:
            # Grab the main executable name
            if plist_dict.get("CFBundleExecutable", None):
                i = plist_dict["CFBundleExecutable"]
                try:
                    main_exe = (i, f"Name of bundle's main executable file: {i}")
                    res.add_line(main_exe[1])
                except UnicodeEncodeError:
                    i = i.encode('utf8', 'replace')
                    main_exe = (i, f"Name of bundle's main executable file: {i}")
                    res.add_line(main_exe[1])

            iden_key_res, unk_key_res = self.parse_plist(plist_dict)
            if iden_key_res:
                res.add_subsection(iden_key_res)
            if unk_key_res:
                res.add_subsection(unk_key_res)
            request.result.add_section(res)

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
                res = ResultSection("PkgInfo Details")
                pkg_info_path = os.path.join(wrk_dir, m.group())
                with open(pkg_info_path, 'r') as f:
                    pkg_info = f.read()
                if pkg_info == "":
                    res.add_line("Empty PkgInfo file. Archive contents may be encrypted.")
                elif len(pkg_info) == 8:
                    # noinspection PyBroadException
                    try:
                        pkgtype = pkg_info[0:4]
                        if pkgtype in pkg_types:
                            pkgtype = pkg_types[pkgtype]
                        creator_code = pkg_info[4:]
                        res = ResultSection("PkgInfo Details")
                        res.add_line(f"Package Type: {pkgtype}; Application Signature: {creator_code}")
                    except Exception:
                        continue
                request.result.add_section(res)

        if main_exe:
            main_exe_reg = (rf'.*{main_exe[0]}$', f"Main executable file {main_exe[0]}")
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
        plist_res = ResultSection("Other Plist File Information (displaying new key-value pairs only)")
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
                        m = pattern.match(full_path)
                        if m is not None:
                            # Already identify main executable file above
                            if not desc.startswith("Main executable file "):
                                if desc.startswith("Plist"):
                                    pres = ResultSection(f"{full_path.replace(wrk_dir, '')}")
                                    isempty, plist_parsed = self.gen_plist_extract(full_path, patterns)
                                    if not isempty and plist_parsed:
                                        iden_key_res, unk_key_res = self.parse_plist(plist_parsed)
                                        # If all keys have already been reported, skip this plist
                                        if not iden_key_res and not unk_key_res:
                                            continue
                                        if iden_key_res:
                                            pres.add_subsection(iden_key_res)
                                        if unk_key_res:
                                            pres.add_subsection(unk_key_res)
                                        plist_res.add_subsection(pres)
                                elif int_files.get(desc, None):
                                    int_files[desc].append(full_path)
                                else:
                                    int_files[desc] = []
                                    int_files[desc].append(full_path)
                            break

        if len(plist_res.subsections) > 0:
            request.result.add_section(plist_res)

        if len(int_files) > 0:
            intf_sec = ResultSection("Files of interest", parent=res)
            for intf_d, intf_p in int_files.items():
                intf_subsec = ResultSection(intf_d, parent=intf_sec)
                for f in intf_p:
                    intf_subsec.add_line(f.replace(f"{wrk_dir}/", ""))
