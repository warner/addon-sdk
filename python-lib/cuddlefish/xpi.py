import os
import zipfile

import simplejson as json

def build_xpi(template_root_dir, manifest, xpi_name,
              harness_options, xpts):
    zf = zipfile.ZipFile(xpi_name, "w", zipfile.ZIP_DEFLATED)

    open('.install.rdf', 'w').write(str(manifest))
    zf.write('.install.rdf', 'install.rdf')
    os.remove('.install.rdf')

    IGNORED_FILES = [".hgignore", "install.rdf", 
                     "application.ini", xpi_name]
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

    for dirpath, dirnames, filenames in os.walk(template_root_dir):
        filenames = list(filter_filenames(filenames))
        dirnames[:] = [dirname for dirname in dirnames
                       if dirname not in IGNORED_DIRS]
        for filename in filenames:
            abspath = os.path.join(dirpath, filename)
            arcpath = abspath[len(template_root_dir)+1:]
            zf.write(abspath, arcpath)

    for abspath in xpts:
        zf.write(str(abspath),
                 str(os.path.join('components',
                                  os.path.basename(abspath))))

    new_resources = {}
    for resource in harness_options['resources']:
        base_arcpath = os.path.join('resources', resource)
        new_resources[resource] = ['resources', resource]
        abs_dirname = harness_options['resources'][resource]
        # Always write the directory, even if it contains no files,
        # since the harness will try to access it.
        dirinfo = zipfile.ZipInfo(base_arcpath + "/")
        dirinfo.external_attr = 0755 << 16L
        zf.writestr(dirinfo, "")
        for dirpath, dirnames, filenames in os.walk(abs_dirname):
            goodfiles = list(filter_filenames(filenames))
            for filename in goodfiles:
                abspath = os.path.join(dirpath, filename)
                arcpath = abspath[len(abs_dirname)+1:]
                arcpath = os.path.join(base_arcpath, arcpath)
                zf.write(str(abspath), str(arcpath))
            dirnames[:] = [dirname for dirname in dirnames
                           if dirname not in IGNORED_DIRS]
    harness_options['resources'] = new_resources

    open('.options.json', 'w').write(json.dumps(harness_options, indent=1,
                                                sort_keys=True))
    zf.write('.options.json', 'harness-options.json')
    os.remove('.options.json')

    zf.close()


import sys
import preflight
import ecdsa
from hashlib import sha256
from cuddlefish.manifest import scan_module

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

class XPIBuilder:
    def __init__(self, xpi_name, app_extension_dir):
        self.zf = zipfile.ZipFile(xpi_name, "w", zipfile.ZIP_DEFLATED)
        self.app_extension_dir = app_extension_dir

    def add_data(self, zipname, data):
        tempname = ".ziptemp"
        f = open(tempname, "wb")
        f.write(data)
        f.close()
        self.zf.write(tempname, zipname)
        os.unlink(tempname)
    def add_file(self, zipname, localfile):
        self.zf.write(localfile, zipname)
    def add_app_extension_file(self, filename):
        self.add_file(filename, os.path.join(self.app_extension_dir, filename))

    def close(self):
        self.zf.close()
        del self.zf

class XPIMapper:
    def __init__(self, app_extension_dir):
        self.map = {} # zipname -> (True, filename) or (False, b64(data))
        self.app_extension_dir = app_extension_dir

    def add_data(self, zipname, data):
        self.map[zipname] = (False, data) # only tolerates unicode strings
    def add_file(self, zipname, localfile):
        self.map[zipname] = (True, localfile)
    def add_app_extension_file(self, filename):
        self.add_file(filename, os.path.join(self.app_extension_dir, filename))

    def close(self):
        pass


class ManifestXPIThingy:
    def __init__(self, pkg_cfg, packages,
                 target_cfg, manifest_rdf, app_extension_dir,
                 keydir, loader_entry, loader_modules, stderr=sys.stderr):
        self.manifest = [] # maps incrementing numbers to ManifestEntry s
        self.pkg_cfg = pkg_cfg
        self.packages = packages
        self.used_packages = set()
        self.stderr = stderr
        self.target_cfg = target_cfg
        self.manifest_rdf = manifest_rdf
        self.app_extension_dir = app_extension_dir
        self.keydir = keydir
        assert loader_entry in loader_modules
        self.loader_entry = loader_entry
        self.loader_modules = loader_modules
        self.modules = {} # maps require() name to index of self.manifest
        self.datamaps = {} # maps package name to DataMap instance
        self.files = [] # maps manifest index to (absfn,absfn) js/docs pair

    def build_xpi(self, xpi_name):
        zf = XPIBuilder(xpi_name, self.app_extension_dir)
        self.build(zf)
        return zf

    def build_map(self):
        zf = XPIMapper(self.app_extension_dir)
        self.build(zf)
        return zf

    def build(self, zf):
        # process the top module, which recurses to process everything it
        # reaches
        self.process_module(*self.find_top(self.target_cfg))

        # stage 1
        zf.add_data("install.rdf", self.manifest_rdf)
        zf.add_app_extension_file("bootstrap.js")
        zf.add_app_extension_file("components/harness.js")

        # stage 2
        loader_manifest = { "entry": self.loader_entry,
                            "manifest": {}, # name to (hash, zipfilename)
                           }
        loader_files = {} # zipfilename to filename
        for name in sorted(self.loader_modules.keys()):
            fn = self.loader_modules[name]
            ign,zipfilename = os.path.split(fn)
            h = hash_file(fn)
            if zipfilename in loader_files:
                raise ValueError("please don't use colliding loader filenames")
            loader_files[zipfilename] = fn
            loader_manifest["manifest"][name] = (h, zipfilename)
        loader_manifest_json = json.dumps(loader_manifest).encode("utf-8")+"\n"
        zf.add_data("loader.json", loader_manifest_json)
        # TODO: loader.json.sig, somehow
        for zipfilename in sorted(loader_files.keys()):
            zf.add_file("loader/" + zipfilename, loader_files[zipfilename])

        misc_data = {"name": self.target_cfg.name,
                     "version": "unknown version",
                     "jid": self.target_cfg["id"],
                     }
        zf.add_data("misc.json", json.dumps(misc_data).encode("utf-8")+"\n")

        # stage 3
        entries = [me.get_entry_for_manifest() for me in self.manifest]
        manifest_json = json.dumps(entries).encode("utf-8")+"\n"
        zf.add_data("manifest.json", manifest_json)

        jid = self.target_cfg["id"]
        sk = preflight.check_for_privkey(self.keydir, jid, self.stderr)
        sig = preflight.my_b32encode(sk.sign(manifest_json))
        vk = preflight.my_b32encode(sk.get_verifying_key().to_string())
        sig_data = json.dumps( (jid, vk, sig) ).encode("utf-8")+"\n"
        zf.add_data("manifest.sig.json", sig_data)

        # build the XPI, keeping things sorted by packagename to be pretty
        used_packages = sorted(self.used_packages)
        for pkgname in used_packages:
            for i,me in enumerate(self.manifest):
                if me.packagename == pkgname:
                    zf.add_file(me.get_js_zipname(), me.js_filename)
            for i,me in enumerate(self.manifest):
                if me.packagename == pkgname:
                    if me.get_docs_zipname():
                        zf.add_file(me.get_docs_zipname(), me.docs_filename)
            if pkgname in self.datamaps:
                dm = self.datamaps[pkgname]
                zf.add_data(dm.data_manifest_zipname, dm.data_manifest)
                for (zipname, fn) in sorted(dm.files_to_copy):
                    zf.add_file(zipname, fn)

        zf.close()


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

    def quick_dump(self):
        manifest = [me.get_entry_for_manifest() for me in self.manifest]

        pkg_length = max([len(me[0]) for me in manifest])
        mod_length = max([len(me[1]) for me in manifest])
        fmtstring = "%%d:  %%%ds   %%%ds .js=[%%4s] .md=[%%4s]   %%s%%s%%s" % \
                    (pkg_length, mod_length)
        for i,me in enumerate(manifest):
            (pkgname, modname, js_hash, docs_hash, reqs, chromep, data_hash) = me
            reqstring = "{%s}" % (", ".join(["%s=%d" % (x,reqs[x]) for x in reqs]))
            chromestring = {True:"+chrome", False:""}[chromep]
            if docs_hash is None: docs_hash = ""
            datastring = ""
            if data_hash:
                datastring = "+data=[%s]" % data_hash[:4]
            print fmtstring % (i, pkgname, modname,  js_hash[:4],docs_hash[:4],
                               reqstring, chromestring, datastring)




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
    jslength = max([len(js_zipname(me[0],me[1])) for me in manifest])
    docslength = max([len(docs_zipname(me[0],me[1])) for me in manifest])
    fmtstring = "%%d:  %%-%ds [%%4s]  /  %%-%ds [%%4s]   %%s%%s%%s" % \
                (jslength, docslength)
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

