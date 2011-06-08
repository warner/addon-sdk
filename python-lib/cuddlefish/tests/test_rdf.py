import unittest
import xml.dom.minidom

from cuddlefish import rdf
def b(s): return s.encode("ascii") # py3 compat, to get bytes from literal


class RDFTests(unittest.TestCase):
    def testBug567660(self):
        obj = rdf.RDF()
        data = u'\u2026'.encode('utf-8')
        x = b('<?xml version="1.0" encoding="utf-8"?><blah>')+data+b('</blah>')
        obj.dom = xml.dom.minidom.parseString(x)
        self.assertEqual(obj.dom.documentElement.firstChild.nodeValue,
                         u'\u2026')
        s = obj.to_bytes().replace(b("\n"), b(""))
        self.assertEqual(s, x.replace(b("\n"),b("")))
