import os, sys, re

COMMENT_PREFIXES = ["//", "/*", "*", "dump("]
QUOTE_COMMENT_PREFIXES = ["//", "/*", "*", "\'", "\"", "dump("]

REQUIRE_RE = r"(?<![\'\"])require\s*\(\s*[\'\"]([^\'\"]+?)[\'\"]\s*\)"

# detect the define idiom of the form:
#   define("module name", ["dep1", "dep2", "dep3"], function() {})
# by capturing the contents of the list in a group.
DEF_RE = re.compile(r"(require|define)\s*\(\s*([\'\"][^\'\"]+[\'\"]\s*,)?\s*\[([^\]]+)\]")

# Out of the async dependencies, do not allow quotes in them.
DEF_RE_ALLOWED = re.compile(r"^[\'\"][^\'\"]+[\'\"]$")

all_requires = []

def process(fn):
    lines = open(fn).readlines()
    for lineno0,line in enumerate(lines):
        lineno = lineno0+1
        for clause in line.split(";"):
            clause = clause.strip()
            iscomment = None
            for commentprefix in COMMENT_PREFIXES:
                if clause.startswith(commentprefix):
                    iscomment = commentprefix
            #if iscomment:
            #    continue
            mo = re.search(REQUIRE_RE, clause)
            if mo:
                modname = mo.group(1)
                all_requires.append( (fn, lineno, modname, iscomment) )

    # define() can happen across multiple lines, so join everyone up.
    wholeshebang = "\n".join(lines)
    for match in DEF_RE.finditer(wholeshebang):
        # this should net us a list of string literals separated by commas
        for strbit in match.group(3).split(","):
            strbit = strbit.strip()
            # There could be a trailing comma netting us just whitespace, so
            # filter that out. Make sure that only string values with
            # quotes around them are allowed, and no quotes are inside
            # the quoted value.
            if strbit and DEF_RE_ALLOWED.match(strbit):
                modname = strbit[1:-1]
                if modname not in ["exports"]:
                    all_requires.append( (fn, "?", modname, "DEF_RE") )

for pkgdir in sys.argv[1:]:
    for section in ["lib", "tests"]:
        for (root, dirs, files) in os.walk(os.path.join(pkgdir, section)):
            for file in files:
                if not file.endswith(".js"):
                    continue
                fn = os.path.join(root, file)
                process(fn)

for (fn, lineno, modname, iscomment) in all_requires:
    if iscomment is None:
        continue
    print (fn, lineno, modname, iscomment)
