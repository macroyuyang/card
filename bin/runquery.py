#!/usr/bin/env python

'''
*******************************************************************************
USAGE:  runquery [--spaceusage] [--help]

*******************************************************************************
'''

import os, re, sys, subprocess, getpass, time, ConfigParser, logging
sys.path.append('/opt/dca/lib')

try:
    from optparse import Option, OptionParser 
    from gppylib.gpparseopts import OptParser, OptChecker
except ImportError, e:    
    sys.exit('Cannot import modules.  Please check that you have sourced greenplum_path.sh.  Detail: ' + str(e))

def runquery(cmd):

    p = subprocess.Popen(cmd, shell = True)

    exitStatus = os.waitpid(p.pid, 0)[1]

    if exitStatus:
        retCode = exitStatus >> 8

        if retCode:
            return 1

    return 0


###### main()
if __name__ == '__main__':

    gphome = os.environ.get('GPHOME')
    if not gphome:
        sys.exit(2)

    parser = OptParser(option_class=OptChecker)
    parser.remove_option('-h')
    parser.add_option('-h', '-?', '--help', action='store_true')
    parser.add_option('-s', '--spaceusage', action='store_true')
    parser.add_option('-u', '--user', type='string')
    parser.add_option('-d', '--dblist',  type='string')

    (options, args) = parser.parse_args()

    if options.help:
        print __doc__
        sys.exit(1)

    cmd=""
    # Get defaults from healthmon config
    if options.spaceusage:
        dblist=options.dblist.split(',')
        if len(dblist) == 0 or not options.user:
            print "Incorrect params"
            sys.exit(0)
        for db in dblist:
            if len(db) == 0:
                continue
            #cmd = """echo -n %s; psql -U %s %s -c "select current_timestamp, relstorage, sum(sotailtablesizedisk)/(1024*1024) as tablesizedisk, sum(sotailtablesizeuncompressed)/(1024*1024) as tablesizeuncompressed, sum(sotailindexessize)/(1024*1024) as indexessize from gp_toolkit.gp_size_of_table_and_indexes_licensing, pg_class where sotailoid = pg_class.oid group by relstorage"  -t -A -F """ % (db, options.user, db)
            cmd = """psql -U %s %s -c "select datname,current_timestamp, relstorage, sum(sotailtablesizedisk)/(1024*1024*1024) as tablesizedisk, sum(sotailtablesizeuncompressed)/(1024*1024*1024) as tablesizeuncompressed, sum(sotailindexessize)/(1024*1024*1024) as indexessize from gp_toolkit.gp_size_of_table_and_indexes_licensing, pg_class, pg_stat_activity where sotailoid = pg_class.oid and procpid=pg_backend_pid() group by relstorage,datname" -t -A -F """ %(options.user, db) 
            runquery(cmd)    
