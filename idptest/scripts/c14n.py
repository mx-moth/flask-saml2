#!/usr/bin/python
from StringIO import StringIO
from lxml import etree

def c14n(src):
    f = StringIO(src)
    tree = etree.parse(f)
    f2 = StringIO()
    tree.write_c14n(f2)
    return f2.getvalue().decode("utf-8")

if __name__=="__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("--fix",
                  action="store_true", dest="fix", default=False,
                  help="Fix file(s) by overwriting original with canonicalized XML.")

    (options, args) = parser.parse_args()
    if len(args) < 1:
        print "c14n - Canonicalize an XML file to stdout"
        print "Usage: c14n [--fix] FILENAMES"
    else:
        for filename in args:
            print 'Processing ' + filename + '...'
            f = open(filename, "r")
            data = f.read()
            f.close()
            if options.fix:
                fixed = c14n(data)
                g = open(filename, "w")
                g.write(fixed)
                g.close()
                print "Fixed " + filename
            else:
                print c14n(data)
