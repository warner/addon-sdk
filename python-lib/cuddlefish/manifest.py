
import os, sys, re
from hashlib import sha256

COMMENT_PREFIXES = ["//", "/*", "*", "\'", "\""]

REQUIRE_RE = r"(?<![\'\"])require\s*\(\s*[\'\"]([^\'\"]+?)[\'\"]\s*\)"

def scan_requirements_with_grep(fn, lines):
    requires = set()
    for line in lines:
        for clause in line.split(";"):
            clause = clause.strip()
            iscomment = False
            for commentprefix in COMMENT_PREFIXES:
                if clause.startswith(commentprefix):
                    iscomment = True
            if iscomment:
                continue
            mo = re.search(REQUIRE_RE, clause)
            if mo:
                modname = mo.group(1)
                requires.add(modname)
    return requires

MUST_ASK_FOR_CHROME =  """\
To use chrome authority, as in line %d in:
 %s
 > %s
You must enable it with:
  let {Cc,Ci,Cu,Cr,Cm} = require('chrome');
"""

CHROME_ALIASES = ["Cc", "Ci", "Cu", "Cr", "Cm"]

def scan_chrome(fn, lines, stderr):
    if fn.endswith("cuddlefish.js") or fn.endswith("securable-module.js"):
        return False, False # these are the loader
    problems = False
    asks_for_chrome = set()
    uses_chrome = set()
    uses_components = False
    uses_chrome_at = []
    for lineno,line in enumerate(lines):
        # note: this scanner is not obligated to spot all possible forms of
        # chrome access. The scanner is detecting voluntary requests for
        # chrome. Runtime tools will enforce allowance or denial of access.
        line = line.strip()
        iscomment = False
        for commentprefix in COMMENT_PREFIXES:
            if line.startswith(commentprefix):
                iscomment = True
        if iscomment:
            continue
        mo = re.search(REQUIRE_RE, line)
        if mo:
            if mo.group(1) == "chrome":
                for alias in CHROME_ALIASES:
                    if alias in line:
                        asks_for_chrome.add(alias)
        alias_in_this_line = False
        for wanted in CHROME_ALIASES:
            if re.search(r'\b'+wanted+r'\b', line):
                alias_in_this_line = True
                uses_chrome.add(wanted)
                uses_chrome_at.append( (wanted, lineno+1, line) )
        
        if not alias_in_this_line and "Components." in line:
            uses_components = True
            uses_chrome_at.append( (None, lineno+1, line) )
            problems = True
            break
    if uses_components or (uses_chrome - asks_for_chrome):
        problems = True
        print >>stderr, ""
        print >>stderr, "To use chrome authority, as in:"
        print >>stderr, " %s" % fn
        for (alias, lineno, line) in uses_chrome_at:
            if alias not in asks_for_chrome:
                print >>stderr, " %d> %s" % (lineno, line)
        print >>stderr, "You must enable it with something like:"
        uses = sorted(uses_chrome)
        if uses_components:
            uses.append("components")
        needed = ",".join(uses)
        print >>stderr, '  const {%s} = require("chrome");' % needed
    return bool(asks_for_chrome), problems

def scan_module(fn, lines, stderr=sys.stderr):
    # barfs on /\s+/ in context-menu.js
    #requires = scan_requirements_with_jsscan(fn)
    requires = scan_requirements_with_grep(fn, lines)
    requires.discard("chrome")
    chrome, problems = scan_chrome(fn, lines, stderr)
    return sorted(requires), chrome, problems

def scan_package(pkg_name, dirname, stderr=sys.stderr):
    manifest = []
    has_problems = False
    for fn in [fn for fn in os.listdir(dirname) if fn.endswith(".js")]:
        modname = fn[:-len(".js")]
        absfn = os.path.join(dirname, fn)
        lines = open(absfn).readlines()
        requires, chrome, problems = scan_module(absfn, lines, stderr)
        manifest.append( (pkg_name, modname, requires, chrome) )
        if problems:
            has_problems = True
    return manifest, has_problems


import zipfile
import simplejson as json
import preflight
import ecdsa

def js_zipname(packagename, modulename):
    return "%s-lib/%s.js" % (packagename, modulename)
def docs_zipname(packagename, modulename):
    return "%s-docs/%s.md" % (packagename, modulename)
def datamap_zipname(packagename):
    return "%s-data.json" % packagename
def datafile_zipname(packagename, datapath):
    return "%s-data/%s" % (packagename, datapath)

class ManifestEntry:
    def get_entry_for_manifest(self):
        return (self.packagename,
                self.modulename,
                self.js_hash,
                self.docs_hash,
                self.requirements,
                self.chrome,
                self.data_hash)
    def get_js_zipname(self):
        return js_zipname(self.packagename, self.modulename)
    def get_docs_zipname(self):
        if self.docs_hash:
            return docs_zipname(self.packagename, self.modulename)
        return None
    # self.js_filename
    # self.docs_filename


def hash_file(fn):
    return sha256(open(fn,"rb").read()).hexdigest()

# things to ignore in data/ directories
IGNORED_FILES = [".hgignore"]
IGNORED_FILE_SUFFIXES = ["~"]
IGNORED_DIRS = [".svn", ".hg", "defaults"]

def filter_filenames(filenames):
    for filename in filenames:
        if filename in IGNORED_FILES:
            continue
        if any([filename.endswith(suffix)
                for suffix in IGNORED_FILE_SUFFIXES]):
            continue
        yield filename

def get_datafiles(datadir):
    # yields pathnames relative to DATADIR, ignoring some files
    for dirpath, dirnames, filenames in os.walk(datadir):
        filenames = list(filter_filenames(filenames))
        # this tells os.walk to prune the search
        dirnames[:] = [dirname for dirname in dirnames
                       if dirname not in IGNORED_DIRS]
        for filename in filenames:
            fullname = os.path.join(dirpath, filename)
            assert fullname.startswith(datadir+"/"), "%s/ not in %s" % (datadir, fullname)
            yield fullname[len(datadir+"/"):]


class DataMap:
    # one per package
    def __init__(self, pkg):
        self.pkg = pkg
        self.name = pkg.name
        self.files_to_copy = []
        datamap = {}
        datadir = os.path.join(pkg.root_dir, "data")
        for dataname in get_datafiles(datadir):
            absname = os.path.join(datadir, dataname)
            zipname = datafile_zipname(pkg.name, dataname)
            datamap[dataname] = hash_file(absname)
            self.files_to_copy.append( (zipname, absname) )
        self.data_manifest = json.dumps(datamap).encode("utf-8")
        self.data_manifest_hash = sha256(self.data_manifest).hexdigest()
        self.data_manifest_zipname = datamap_zipname(pkg.name)

class ManifestXPIThingy:
    def build(self, xpi_name, pkg_cfg, packages, target_cfg, keydir,
              stderr=sys.stderr):
        self.manifest = [] # maps incrementing numbers to ManifestEntry s
        self.pkg_cfg = pkg_cfg
        self.packages = packages
        self.used_packages = set()
        self.stderr = stderr
        self.modules = {} # maps require() name to index of self.manifest
        self.datamaps = {} # maps package name to DataMap instance
        self.files = [] # maps manifest index to (absfn,absfn) js/docs pair

        # process the top module, which recurses to process everything it
        # reaches
        self.process_module(*self.find_top(target_cfg))

        # now build an XPI out of it
        zf = zipfile.ZipFile(xpi_name, "w", zipfile.ZIP_DEFLATED)
        def add_data(zipname, data):
            tempname = ".ziptemp"
            f = open(tempname, "wb")
            f.write(data)
            f.close()
            zf.write(tempname, zipname)
            os.unlink(tempname)
        def add_file(zipname, localfile):
            zf.write(localfile, zipname)

        add_data("loader", "fake loader\n")

        misc_data = {"name": target_cfg.name,
                     "version": "unknown version",
                     }
        add_data("misc.json", json.dumps(misc_data).encode("utf-8"))

        entries = [me.get_entry_for_manifest() for me in self.manifest]
        manifest_json = json.dumps(entries).encode("utf-8")
        add_data("manifest.json", manifest_json)

        jid = target_cfg["id"]
        sk = preflight.check_for_privkey(keydir, jid, self.stderr)
        sig = preflight.my_b32encode(sk.sign(manifest_json))
        vk = preflight.my_b32encode(sk.get_verifying_key().to_string())
        sig_data = json.dumps( (jid, vk, sig) ).encode("utf-8")
        add_data("manifest.sig.json", sig_data)

        # build the XPI, keeping things sorted by packagename to be pretty
        used_packages = sorted(self.used_packages)
        for pkgname in used_packages:
            for i,me in enumerate(self.manifest):
                if me.packagename == pkgname:
                    add_file(me.get_js_zipname(), me.js_filename)
            for i,me in enumerate(self.manifest):
                if me.packagename == pkgname:
                    if me.get_docs_zipname():
                        add_file(me.get_docs_zipname(), me.docs_filename)
            if pkgname in self.datamaps:
                dm = self.datamaps[pkgname]
                add_data(dm.data_manifest_zipname, dm.data_manifest)
                for (zipname, fn) in sorted(dm.files_to_copy):
                    add_file(zipname, fn)

        zf.close()
        return self.manifest

    def find_top(self, target_cfg):
        for libdir in target_cfg.lib:
            n = os.path.join(target_cfg.root_dir, libdir, target_cfg.main+".js")
            if os.path.exists(n):
                top_js = n
                break
        else:
            raise KeyError("unable to find main module '%s.js' in top-level package" % target_cfg.main)
        n = os.path.join(target_cfg.root_dir, "README.md")
        if os.path.exists(n):
            top_docs = n
        else:
            top_docs = None
        return (target_cfg, target_cfg.main, top_js, top_docs)

    def process_module(self, pkg, modulename, js_filename, docs_filename):
        # create and claim the manifest row first
        mod_index = len(self.manifest)
        me = ManifestEntry()
        self.manifest.append(me)

        self.used_packages.add(pkg.name)
        me.packagename = pkg.name
        me.modulename = modulename
        me.js_filename = js_filename
        me.js_hash = hash_file(me.js_filename)
        if docs_filename:
            me.docs_filename = docs_filename
            me.docs_hash = hash_file(me.docs_filename)
        else:
            me.docs_filename = None
            me.docs_hash = None
        js_lines = open(me.js_filename,"r").readlines()
        requires, chrome, problems = scan_module(me.js_filename, js_lines,
                                                 self.stderr)
        me.chrome = chrome
        if "self" in requires:
            # this might reference bundled data, so:
            #  1: hash that data, add the hash as a dependency
            #  2: arrange for the data to be copied into the XPI later
            if pkg.name not in self.datamaps:
                self.datamaps[pkg.name] = DataMap(pkg)
            me.data_hash = self.datamaps[pkg.name].data_manifest_hash
        else:
            me.data_hash = None

        # 'reqnums' is updated below, on the way out of the depth-first
        # traversal of the module graph
        me.requirements = reqnums = {}

        # then other modules can create their own rows
        for reqname in requires:
            # when two modules require() the same name, do they get a shared
            # instance? This is a deep question. For now say yes.
            if reqname not in self.modules:
                found = self.find_module_and_docs(reqname)
                req_index = self.process_module(*found)
                self.modules[reqname] = req_index
            reqnums[reqname] = self.modules[reqname]
        return mod_index

    def find_module_and_docs(self, name):
        # return (pkg, name, js_filename, docs_filename)
        for pkgname in self.packages:
            pkg = self.pkg_cfg.packages[pkgname]
            if isinstance(pkg.lib, basestring):
                libs = [pkg.lib]
            else:
                libs = pkg.lib
            for libdir in libs:
                js = os.path.join(pkg.root_dir, libdir, name+".js")
                if os.path.exists(js):
                    maybe_docs = os.path.join(pkg.root_dir, "docs", name+".md")
                    docs = None
                    if os.path.exists(maybe_docs):
                        docs = maybe_docs
                    return (pkg, name, js, docs)
        raise KeyError("unable to find module '%s' in any package" % name)


def dump_manifest(manifest_file):
    zf = zipfile.ZipFile(open(manifest_file, "rb"))
    #for zi in zf.infolist():
    #    print zi.filename

    print "checking manifest signature.."
    manifest_data = zf.open("manifest.json").read()
    sig_data = zf.open("manifest.sig.json").read()
    (jid, vk_b32, sig_s) = json.loads(sig_data.decode("utf-8"))
    vk = ecdsa.VerifyingKey.from_string(preflight.my_b32decode(vk_b32),
                                        curve=ecdsa.NIST256p)
    sig = preflight.my_b32decode(sig_s)
    vk.verify(sig, manifest_data)
    manifest = json.loads(manifest_data.decode("utf-8"))

    print "checking hashes.."
    for i,me in enumerate(manifest):
        (pkgname, modname, js_hash, docs_hash, reqs, chromep, data_hash) = me
        js = js_zipname(pkgname, modname)
        js_hash2 = sha256(zf.open(js).read()).hexdigest()
        if js_hash != js_hash2:
            print "BADHASH", js, js_hash, js_hash2
        if docs_hash:
            docs = docs_zipname(pkgname, modname)
            docs_hash2 = sha256(zf.open(docs).read()).hexdigest()
            if docs_hash != docs_hash2:
                print "BADHASH", docs, docs_hash, docs_hash2
        if data_hash:
            datamap_zn = datamap_zipname(pkgname)
            datamap = zf.open(datamap_zn).read()
            data_hash2 = sha256(datamap).hexdigest()
            if data_hash != data_hash2:
                print "BADHASH", datamap_zn, data_hash, data_hash2

            datamap_json = json.loads(datamap.decode("utf-8"))
            for datafile_pathname, datafile_hash in datamap_json.items():
                datafile_zn = datafile_zipname(pkgname, datafile_pathname)
                data = zf.open(datafile_zn).read()
                datafile_hash2 = sha256(data).hexdigest()
                if datafile_hash != datafile_hash2:
                    print "BADHASH", datafile_zn, datafile_hash, datafile_hash2
                


    print "MANIFEST:"
    length = max([len(docs_zipname(me[0],me[1])) for me in manifest])
    fmtstring = "%%d:  %%%ds [%%4s]   %%%ds [%%4s]   %%s%%s%%s" % (length, length)
    for i,me in enumerate(manifest):
        (pkgname, modname, js_hash, docs_hash, reqs, chromep, data_hash) = me
        reqstring = "{%s}" % (", ".join(["%s=%d" % (x,reqs[x]) for x in reqs]))
        chromestring = {True:"+chrome", False:""}[chromep]
        if docs_hash is None: docs_hash = ""
        datastring = ""
        if data_hash:
            datastring = "+data=[%s]" % data_hash[:4]
        js = js_zipname(pkgname, modname)
        docs = docs_zipname(pkgname, modname)
        print fmtstring % (i, js,js_hash[:4],  docs,docs_hash[:4], reqstring,
                           chromestring, datastring)

if __name__ == '__main__':
    for fn in sys.argv[1:]:
        requires,chrome,problems = scan_module(fn, open(fn).readlines())
        print
        print "---", fn
        if problems:
            print "PROBLEMS"
            sys.exit(1)
        print "chrome: %s" % chrome
        print "requires: %s" % (",".join(requires))

