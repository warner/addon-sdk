
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

class ManifestXPIThingy:
    def build(self, pkg_cfg, packages, target_cfg, keydir, stderr=sys.stderr):
        self.manifest = []
        # keys are incrementing numbers
        # values are ( JSfilename, H(JSfile), MDfilename, H(MDfile),
        #              {reqname: manifestkey, ..}, chromep )
        self.pkg_cfg = pkg_cfg
        self.packages = packages
        self.stderr = stderr
        self.modules = {} # maps require() name to index of self.manifest
        self.files = [] # maps manifest index to (absfn,absfn) js/docs pair

        # process the top module, which recurses to process everything it
        # reaches
        self.process_module(self.find_top(target_cfg))

        # now build an XPI out of it
        def add_data(zf, zipname, data):
            tempname = ".ziptemp"
            f = open(tempname, "wb")
            f.write(data)
            f.close()
            zf.write(tempname, zipname)
            os.unlink(tempname)
        zf = zipfile.ZipFile("%s.xpi" % target_cfg.name, "w", zipfile.ZIP_DEFLATED)

        add_data(zf, "loader", "fake loader\n")

        misc_data = {"name": target_cfg.name,
                     "version": "unknown version",
                     }
        add_data(zf, "misc.json", json.dumps(misc_data).encode("utf-8"))

        manifest_json = json.dumps(self.manifest).encode("utf-8")
        add_data(zf, "manifest.json", manifest_json)

        jid = target_cfg["id"]
        sk = preflight.check_for_privkey(keydir, jid, self.stderr)
        sig = preflight.my_b32encode(sk.sign(manifest_json))
        vk = preflight.my_b32encode(sk.get_verifying_key().to_string())
        sig_data = json.dumps( (jid, vk, sig) ).encode("utf-8")
        add_data(zf, "manifest.sig.json", sig_data)

        for i,m in enumerate(self.manifest):
            js,doc = self.files[i]
            (js_zipname, js_hash, docs_zipname, docs_hash, reqnums, chrome) = m
            zf.write(js, js_zipname)
            if doc:
                zf.write(doc, docs_zipname)
        zf.close()
        return self.manifest

    def find_top(self, target_cfg):
        top_js = self.find_module_in_package(target_cfg, target_cfg.main)
        top_docs = self.find_top_docs(target_cfg)
        return top_js, top_docs

    def process_module(self, (js, docs)):
        js_hash = sha256(open(js,"rb").read()).hexdigest()
        js_zipname = os.path.basename(js)#"?"
        if docs:
            docs_hash = sha256(open(docs,"rb").read()).hexdigest()
            docs_zipname = os.path.basename(docs)
        else:
            docs_hash = None
            docs_zipname = None
        js_lines = open(js,"r").readlines()
        requires, chrome, problems = scan_module(js, js_lines, self.stderr)
        # create and claim the manifest row first
        mod_index = len(self.manifest)
        reqnums = {} # this is updated below, on the way out of the
                     # depth-first traversal of the module graph
        m = (js_zipname, js_hash, docs_zipname, docs_hash, reqnums, chrome)
        self.manifest.append(m)
        self.files.append( (js, docs) )
        # then other modules can create their own rows
        for reqname in requires:
            # when two modules require() the same name, do they get a shared
            # instance? This is a deep question. For now say yes.
            if reqname not in self.modules:
                (reqjs, reqdocs) = self.find_module_and_docs(reqname)
                req_index = self.process_module( (reqjs, reqdocs) )
                self.modules[reqname] = req_index
            reqnums[reqname] = self.modules[reqname]
            
        return mod_index


    def find_module_and_docs(self, name):
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
                    return (js, docs)
        raise KeyError("unable to find module '%s' in any package" % name)

    def find_module_in_package(self, package, name):
        for libdir in package.lib:
            n = os.path.join(package.root_dir, libdir, name+".js")
            if os.path.exists(n):
                return n
        raise KeyError("unable to find module '%s' in package '%s'" %
                       (name, package.name))

    def find_docs(self, package, name):
        n = os.path.join(package.root_dir, "docs", name+".md")
        if os.path.exists(n):
            return n
        return None

    def find_top_docs(self, package):
        n = os.path.join(package.root_dir, "README.md")
        if os.path.exists(n):
            return n
        return None


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
    for i,mi in enumerate(manifest):
        (js,hjs,docs,hdocs,reqs,chromep) = mi
        hjs2 = sha256(zf.open(js).read()).hexdigest()
        if hjs2 != hjs:
            print "BADHASH", js, hjs, hjs2
        if docs:
            hdocs2 = sha256(zf.open(docs).read()).hexdigest()
            if hdocs2 != hdocs:
                print "BADHASH", docs, hdocs, hdocs2

    print "MANIFEST:"
    length = max([len(mi[0]) for mi in manifest])
    fmtstring = "%%d:  %%%ds [%%s]   %%%ds [%%s]   %%s%%s" % (length, length)
    for i,mi in enumerate(manifest):
        (js,hjs,docs,hdocs,reqs,chromep) = mi
        reqstring = "{%s}" % (", ".join(["%s=%d" % (x,reqs[x]) for x in reqs]))
        print fmtstring % (i, js,hjs[:4],  docs,hdocs[:4], reqstring,
                           {True:"+chrome", False:""}[chromep])

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

