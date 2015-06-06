import web
import os, sys, datetime, locale, time, subprocess, warnings, re, pwd
import gplog
from pygresql import pg
import shutil

log = None
gp_log_alert_level = None
pguser = 'gpmon'
pgdatabase = 'gpperfmon'
pgpass = os.environ.get('PGPASSWORD', '')
pgport = os.environ.get('PGPORT', '5432')
pgport = int(pgport)
pghost = os.environ.get('PGHOST', 'localhost')
master_data_dir = os.environ.get('MASTER_DATA_DIRECTORY')
gphome = os.environ.get('GPHOME')
gpperfmonhome = os.environ.get('GPPERFMONHOME')
pghost_logon = os.environ.get('PGHOST_LOGON', pghost)
os.environ["PGAPPNAME"] = "gpmonws"
path=''
ssh_full_path = 'ssh'
auth_mech=''

NONGPDB_DISK_SPACE_USAGE_SQL = r"select sample_time, hostname, filesystem, hosttype, round((total_bytes::real/1073741824)::numeric, 2) as total_bytes, round((bytes_used::real/1073741824)::numeric, 2) as bytes_used, round((bytes_available::real/1073741824)::numeric, 2) as bytes_available from (select ctime as sample_time, * from diskspace_history where ctime in (select distinct max(ctime) from diskspace_history)) a, (select customerhostname, hosttype from  %s.dca_hostmapping) hostmap where filesystem IN ('/data', '/data1', '/data2', '/data3', '/data4', '/data5', '/data6', '/data7', '/data8', '/data9', '/data10', '/data11', '/data12') and hostname = customerhostname and hosttype IN (%s)"
NO_SUMMARY_WRAP = r'select max(sample_time) as sample_time, count(distinct(hostname)) as hosts_current, hosttype as hostname, SUM(total_bytes) as total_bytes, sum(bytes_used) as bytes_used, sum(bytes_available) as bytes_available from (%s) as c group by hosttype'
NO_SUMMARY_WRAP_GPDB = r'select max(sample_time) as sample_time, count(distinct(hostname)) as hosts_current, hosttype as hostname, oid, SUM(total_bytes) as total_bytes, sum(bytes_used) as bytes_used, sum(bytes_available) as bytes_available from (%s) as c group by hosttype, oid'
GPDB_DISK_SPACE_USAGE_SQL = r"select sample_time, hostname, filesystem, hosttype, oid, round((total_bytes::real/1073741824)::numeric, 2) as total_bytes, round((bytes_used::real/1073741824)::numeric, 2) as bytes_used, round((bytes_available::real/1073741824)::numeric, 2) as bytes_available from (select ctime as sample_time, * from diskspace_history where ctime in (select distinct max(ctime) from diskspace_history)) a, %s.fsmapcache, (select distinct(hostname) as customerhostname, case content when -1 then 'master' else 'sdw' end as hosttype from gp_segment_configuration group by hostname, content) gseg where mount = filesystem and hostname = customerhostname and hostname=host and hosttype in (%s)" 

filter_type_map = {
        "hadoop" : r"'hdw', 'hdm', 'hdc', 'hbw'",
        "gpdb" : r"'master', 'sdw'",
        "hdw": r"'hdw'",
        "hdm": r"'hdm'",
        "hdc": r"'hdc'",
        "hbw": r"'hbw'",
        "etl": r"'etl', 'dia'",
        "dia": r"'etl', 'dia'",
        "master": r"'master'",
        "sdw": r"'sdw'"
}

try:
    path = '%s/gpperfmon/data' % master_data_dir
except:
    print 'MASTER_DATA_DIRECTORY env not set'

warnings.simplefilter('ignore', DeprecationWarning)
try:
    incpath = "%s/bin/lib" % gphome
    sys.path.append(incpath)
    import pexpect
except ImportError, e:    
    log.msg('Import error for paramiko')

# Use this to throw exceptions related to unavailability of the DB
class GPDBError(Exception):
    def __init__(self, value):
        self.value = value 
    def __str__(self):
        return repr(self.value)

class NoDataError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

def set_ssh_full_path(path):
    global ssh_full_path
    ssh_full_path = path

def set_logger(weblog):
    global log
    log = weblog

def raise_db_error(text):
    raise GPDBError, text

def run_remote_command2(host, cmdStr):
    '''
    Run a remote command.
    
    Returns:
        rc -- return code
        stdout -- standard out
        stderr -- standard error
    '''

    remoteCmdStr = "%s -o 'StrictHostKeyChecking no' %s \"%s\"" % (ssh_full_path, host, cmdStr)
    try:
        p = subprocess.Popen(remoteCmdStr, shell=True, executable="/bin/bash", stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        output = p.communicate()

        if p.returncode:
            log.msg('Error remote command %s: %s' % ( remoteCmdStr, output[1]) )

        return (p.returncode, output[0], output[1])

    except Exception, e:
        log.msg('Exception running remote command %s: %s' % (remoteCmdStr, e.__str__()))
        raise
    except:
        log.msg("Unexpected error running command %s: %s" % (remoteCmdStr, sys.exc_info()[0]))
        raise

def get_quantum(username, password):
    rows = execute_query('SELECT quantum FROM system_now LIMIT 1', username, password)
    if rows and len(rows) > 0:
        return (rows[0])['quantum']
    else:
        return 15

def grant_default_permissions():

    tables = ['database_history', 'diskspace_history', 'emcconnect_history', 'iterators_history',
              'log_alert_history', 'queries_history', 'system_history', 'gp_log_master_ext',
              'database_now', 'database_tail', 'diskspace_now', 'diskspace_tail',
              'iterators_now', 'iterators_tail', 'log_alert_now', 'log_alert_tail',
              'master_data_dir', 'queries_now', 'queries_tail', 'system_now', 'system_tail']
              
    for t in tables:
        GRANT_SQL = """GRANT ALL ON TABLE %s TO public""" % t
        log.msg(GRANT_SQL)
        try:
            rows = execute_query(GRANT_SQL, pguser, None, True)
        except:
            log.msg("grant SQL failed for table '%s'" % t)
            pass

def is_operator_role(user_to_check, access_user):

    CHECK_SQL = """SELECT COUNT(*) FROM pg_auth_members WHERE 
                    roleid IN (SELECT oid FROM pg_roles WHERE rolname = 'gpcc_operator') 
                    AND member IN (SELECT oid FROM pg_roles WHERE rolname='%s' ); """  % user_to_check

    log.debug(CHECK_SQL)

    rows = execute_query(CHECK_SQL, pguser, None)

    cnt = len(rows)

    if cnt != 1:
        log.msg("error querying for operator group count(%d) (%s)" % (cnt, CHECK_SQL))

    log.debug("output %s" % rows)

    if rows[0]['count']: 
        return True
    else:
        return False

# return (GPDBUsername, userStatus)
# userStatus => returns true if user exists in GPDB 
def getGPDBUsername(username):
    MAPP_GPDB_USER_SQL = """SELECT username FROM user_cert_mapping WHERE mapping='%s'; """ % username
    res = ('NoUser', False)
    rows = execute_query( MAPP_GPDB_USER_SQL, pguser, None)
    if len(rows) == 1:
       log.msg("data %s" % rows[0]['username'])
       res = (rows[0]['username'], True)
    return res

# return (validRole, issuperuser, isoperator, message)
# has_kerb flag is use to skip the check for trust login in case of kerberos environment
def get_role(username, password, has_kerb):
    
    res = (False, False, False, 'Incorrect username/password')

    is_operator = is_operator_role(username, pguser)

    # Now check with password 
    try:
        log.debug('connect to database user=%s host=%s port=%s database=%s' % (username,pghost_logon,pgport,pgdatabase))
        if auth_mech == 'pki' :
            auth_conn = pg.connect(dbname=pgdatabase, host=pghost_logon, port=pgport, user=pguser, passwd=pgpass)
        else :
            auth_conn = pg.connect(dbname=pgdatabase, host=pghost_logon, port=pgport, user=username, passwd=password)
        auth_conn.close()
    except:
        clearKerberos()
        log.msg('failed connecting to database using user=%s host=%s port=%s database=%s password=XXXXXXX' % (username,pghost_logon,pgport,pgdatabase))
        return res

    try:
        # Then use our superuser connection to check the user's authorization level
        check_auth_query = 'select rolsuper from pg_roles where rolname = \'%s\'' % username
        for r in execute_query(check_auth_query, username, password):
            superuser = False
            if r['rolsuper'] == 't':
                superuser = True
            res = (True, superuser, is_operator, '')
            break
    except Exception:
        log.msg('error: checking for superuser with query; %s' % check_auth_query)
        raise_db_error('Exception during query: %s ' % check_auth_query)

    return res



def removeKrbTicket(fileName) :
    kerb5Ticket = web.cookies().get('GP_Kerb_Ticket', '')
    usrName =  web.ctx.env['REMOTE_USER'].split('@')[0]
    krbTicket_directory = os.path.join(os.getcwd(), '..', 'sessions/')
    if kerb5Ticket == '' :
       ticketPath = krbTicket_directory+fileName.split('/')[2]+'_'+usrName
       files = os.listdir(krbTicket_directory+'/')
       for file in files :
           if re.search(r"_"+usrName+"$",file) :
               os.remove(krbTicket_directory+file)
               log.msg("Deleted main file %s" % file)
       shutil.copy2(web.ctx.env['KRB5CCNAME'], ticketPath)
       web.setcookie('GP_Kerb_Ticket', ticketPath)
       kerb5Ticket = ticketPath
       os.environ['KRB5CCNAME'] = kerb5Ticket
       os.remove(fileName)
       log.debug("Deleted actual file :%s Krb5Ticket : %s " % (fileName,kerb5Ticket))
    else :
       os.remove(fileName)
       log.debug("Deleted file :%s Krb5Ticket : %s " % (fileName,kerb5Ticket,))

# To unset session cookie
def clearKerberos():
    os.environ['KRB5CCNAME'] = ''
    web.setcookie('GP_Kerb_Ticket', '', 1)
    return


def hosts(username, password):
    rows = []
    try:
        query = 'select distinct(hostname) from system_now'
        for r in execute_query(query, username, password):
            rows.append(r['hostname'])
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows


def get_procpid(sessionid, querycount):
    query = "select procpid, usename from pg_stat_activity, queries_now where sess_id=%s and ccnt=%s and queries_now.ssid=%s and queries_now.tsubmit=date_trunc('second', pg_stat_activity.query_start) and (queries_now.status='start'or queries_now.status='submit')" % (sessionid, querycount, sessionid)

    try:
        # use superuser to cancel query
        # assumption is the user is validated to be OPERATOR or SUPERUSER in the webservice
        rows = execute_query(query, pguser, None)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def cancel_query(procpid):
    query = "select pg_cancel_backend(%s) -- gpmonws cancel query" % procpid;
    try:
        # use superuser to cancel query
        # assumption is the user is validated to be OPERATOR or SUPERUSER in the webservice
        rows = execute_query(query, pguser, None)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def get_query_priority(username, password, sessionid, querycount):
    query = "select rqppriority from gp_toolkit.gp_resq_priority_statement where rqpsession='%s' and rqpcommand='%s'" %(sessionid, querycount)
    try:
        rows = execute_query(query, username, password)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def set_query_priority(username, password, sessionid, commandid, priority):
    query = "select gp_adjust_priority(%s, %s, \'%s\')" %(sessionid, commandid, priority)
    try:
        rows = execute_query(query, username, password)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def get_filespace_list(username, password):
    query = "select fsname from pg_filespace"
    try:
        rows = execute_query(query, username, password)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def _system_consolidate_aggregate(rows):
    td = {}   #time dimension
    tab = {}  #table where the key is composed of host and time

    x = None
    for r in rows:
        t = r['sample_time']
        td[t] = 1;
        tab[t] = r
        x = r

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = x.keys();
        ckeys.sort()

    tkeys = td.keys(); tkeys.sort()
    return (tkeys, None, ckeys, tab)


def _system_consolidate_nonaggregate(rows):
    td = {}   #time dimension
    hd = {}   #host dimension
    tab = {}  #table where the key is composed of host and time

    x = None
    for r in rows:
        (h, t) = (r['hostname'], r['sample_time'])
        td[t] = 1; hd[h] = 1
        tab[(h,t)] = r
        x = r

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = filter(lambda i: i != 'hostname', x.keys())
        ckeys.sort()

    tkeys = td.keys(); tkeys.sort()
    hkeys = hd.keys(); hkeys.sort()
    return (tkeys, hkeys, ckeys, tab)


def _queries_consolidate(rows):
    # verify the result set from the SQL query is not empty
    if not rows:
        return ([], [], {}, 0)

    td = {}   #time dimension
    tab = {}  #table where the key is composed of time

    x = None
    row_count = 0
    for r in rows:
        t = '%s-%s-%s' % (r['tmid'], r['ssid'], r['ccnt'])
        td[t] = 1
        tab[t] = r
        x = r
        row_count += 1

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = filter(lambda i: i != 'query_hash' and i != 'length' and i != 'query_plan' and i != 'tmid' and i != 'ssid' and i != 'ccnt', x.keys())
        ckeys.sort()

    tkeys = td.keys(); tkeys.sort()
    return (tkeys, ckeys, tab, row_count)


def _queryplan_consolidate(rows):

    # verify the result set from the SQL query is not empty
    if not rows:
        return ([], {}, {}, None)

    tree = {} # tree containing the query plan hierarchy
    tab = {} 
    
    x = None
    for r in rows:
        # retrieve parent and child node IDs
        (p, c) = (r['pnid'], r['nid'])
        # create a hash table indexed by parent and child node ID
        tab[c] = r
        x = r
        # insert new child node into hash table
        if p in tree:
            tree[p].append(c)
        else:
            tree[p] = [c]

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = filter(lambda i: i != 'tmid' and i != 'ssid' and i != 'ccnt' and i != 'nid' and i != 'pnid', x.keys())
        ckeys.sort()

    # determine the root of the tree
    nkeys = tree.keys()
    nkeys.sort()
    root = nkeys[0]

    return (ckeys, tab, tree, root)


def _iterator_consolidate(rows):
    # verify the result set from the SQL query is not empty
    if not rows:
        return ([], [], {})

    segd = {} #time dimension
    tab = {}  #table where the key is composed of segment id

    x = None
    for r in rows:
        s = r['segid']
        segd[s] = 1
        tab[s] = r
        x = r

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        # filter out segment id
        ckeys = filter(lambda i: i != 'segid', x.keys())
        ckeys.sort()

    skeys = segd.keys(); skeys.sort()
    return (skeys, ckeys, tab)


def _database_consolidate(rows):
    td = {}   #time dimension
    tab = {}  #table where the key is composed time

    x = None
    for r in rows:
        t = r['sample_time']
        td[t] = 1
        tab[t] = r
        x = r

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = x.keys();
        ckeys.sort()

    tkeys = td.keys(); tkeys.sort()
    return (tkeys, ckeys, tab)


def execute_query(query, username, password, modifytable=False, database = None):
    if database is None:
        database = pgdatabase

    try:
        if auth_mech == 'pki' :
            conn = pg.connect(dbname=database, host=pghost, port=pgport, user=pguser, passwd=pgpass)
        else :
            conn = pg.connect(dbname=database, host=pghost, port=pgport, user=username, passwd=password)
    except Exception, e:
        clearKerberos()
        log.msg('error connecting to GPDB: %s for query: %s' % (e.__str__().strip(), query))
        log.msg("dbname=%s, host=%s, port=%s, user=%s"  % (pgdatabase, pghost, pgport, username))
        raise_db_error('Connection error for query: %s' % query)
    except:
        clearKerberos()
        log.msg('error connecting to GPDB for query: %s' % (query))
        log.msg("dbname=%s, host=%s, port=%s, user=%s" % (pgdatabase, pghost, pgport, username))
        raise_db_error('Connection error for query: %s' % query)

    try:
        q = conn.query(query)
        if not modifytable:
            return q.dictresult()
        else:
            return 
    except Exception, e:
        log.msg('error during query (%s): %s' % (query, e.__str__().strip()))
        raise_db_error('Exception during query: %s %s' % (query, e.__str__().strip()))
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s %s' % (query, e.__str__().strip()))

    return []

# perform a query that we expect ro return a single row with a single value only
def execute_single_value_query(query, username, password):

    rows = execute_query(query, username, password)
    if len(rows) != 1:
        log.msg('Expected to get one row from query (%s) but got %d rows' % (query, len(rows)))
        raise_db_error('Expected to get one row from query (%s) but got %d rows' % (query, len(rows)))
        
    firstRow = rows[0]

    if len(firstRow.keys()) != 1:
        log.msg('Expected to get one column from query (%s) but got %d columns' % (query, len(firstRow.keys())))
        raise_db_error('Expected to get one row from query (%s) but got %d rows' % (query, len(firstRow.keys())))

    key = firstRow.keys()[0]
    value = firstRow[key]
    return value

def system_now(remote, username, password, type):
    nonaggregate = 'no'
    interval_code = 7 # magic number
    filter = hosttype_filter_string(type, False)

    query = system_sql('system_now', filter, interval_code, nonaggregate)

    rows = execute_query(query, username, password)

    return _system_consolidate_nonaggregate(rows)

def system_sql(table, filter, interval_code, aggregate):
    columns = [ 'mem_total', 'mem_used', 'mem_actual_used', 'mem_actual_free',
                'swap_total', 'swap_used', 'swap_page_in', 'swap_page_out',
                'cpu_user', 'cpu_sys', 'cpu_idle', 'load0', 'load1', 'load2',
                'disk_ro_rate', 'disk_wo_rate', 'disk_rb_rate',
                'disk_wb_rate', 'net_rp_rate', 'net_wp_rate', 'net_rb_rate',
                'net_wb_rate']

    # Scale some of the fields to MBytes
    scaling = [ 1048576, 1048576, 1048576, 1048576,
                1048576, 1048576, 1, 1,
                1, 1, 1, 1, 1, 1, 
                1, 1, 1048576, 
                1048576, 1, 1, 1048576, 
                1048576 ]

    # Time aggregation expressions for each level of aggregration
    #  1min, 5min, 1hr, 6hr, 1day, 1wk, 6mth
    itvl_sql = ["date_trunc('minute', ctime)",   
                "date_trunc('hour', ctime)+(((trunc(date_part('minute', ctime)/5)*5)::text||' minutes')::interval)",
                "date_trunc('hour', ctime)",   
                "date_trunc('day', ctime)+(((trunc(date_part('hour', ctime)/6)*6)::text||' hours')::interval)",
                "date_trunc('day', ctime)",   
                "date_trunc('week', ctime)",   
                "date_trunc('year', ctime)+(((trunc(date_part('month', ctime)/6)*6)::text||' months')::interval)",
                "ctime"]

    if aggregate == 'yes':
        query_fragment = "select %s as sample_time" % itvl_sql[interval_code]
        for i in range(len(columns)):
            if scaling[i] == 1:
                query_fragment += ", round(avg(%s)::numeric, 2) as %s" % (columns[i], columns[i])
            else:
                query_fragment += ", round((avg(%s)::real/%s)::numeric, 2) as %s" % (columns[i], scaling[i], columns[i])

        query_fragment += " from %s %s" % (table, filter)
        query_fragment += " group by sample_time"

    else:
        query_fragment = "select %s as sample_time, hostname" % itvl_sql[interval_code]
        for i in range(len(columns)):
            if scaling[i] == 1:
                query_fragment += ", round(avg(%s)::numeric, 2) as %s" % (columns[i], columns[i])
            else:
                query_fragment += ", round((avg(%s)::real/%s)::numeric, 2) as %s" % (columns[i], scaling[i], columns[i])

        query_fragment += " from %s %s" % (table, filter)
        query_fragment += " group by hostname, sample_time"

    return query_fragment

def hosttypemapping_filter_string(type, addToExisting):
    
    filter = ''
    if addToExisting:
        filter = 'AND '
    else:
        filter = ' WHERE '

    if type == 'all':
        filter = ''
    elif type == 'hdw':
        filter +=  "(hosttype = 'hdw')"
    elif type == 'hdc':
        filter +=  "(hosttype = 'hdc')"
    elif type == 'hdm':
        filter +=  "(hosttype = 'hdm')"
    elif type == 'hadoop':
        filter +=  "(hosttype = 'hdw' or hosttype = 'hdc' or hosttype = 'hdm' or hosttype = 'hbw')"
    elif type == 'master':
        filter +=  "(hosttype = 'master')"
    elif type == 'sdw': 
        filter +=  "(hosttype = 'sdw')"
    elif (type == 'etl' or type == 'dia'):
        filter +=  "(hosttype in ('etl', 'dia'))"
    elif type == 'gpdb':
        filter +=  "(hosttype = 'master' or hosttype = 'smdw' or hosttype = 'sdw')"
    elif type == 'hbw':
        filter +=  "(hosttype = 'hbw')"
    else:
        raise Exception("unexpected type '%s' in hosttypemapping_filter_string method" % type)

    return filter


def hosttype_filter_string(type, addToExisting):

    filter = ''
    if addToExisting:
        filter = 'AND '
    else:
        filter = ' WHERE '

    if type == 'all':
        filter = ''
    elif type == 'hdw':
        filter +=  "(hostname like 'hdw%' or hostname like 'hdc%')"
    elif type == 'hdm':
        filter +=  "(hostname like 'hdm%')" 
    elif type == 'hbw':
        filter +=  "(hostname like 'hbw%')" 
    elif type == 'hadoop':
        filter +=  "(hostname like 'hdw%' or hostname like 'hdc%' or hostname like 'hdm%' or hostname like 'hbw%')"
    elif type == 'masters':
        filter +=  "(hostname = 'mdw' or hostname = 'smdw')" 
    elif type == 'segments':
        filter +=  "(hostname like 'sdw%')" 
    elif type == 'dia':
        filter +=  "(hostname like 'etl%')" 
    else:
        raise Exception("unexpected type '%s' in hosttype_filter_string method" % type)

    return filter


def system_history(stime, etime, interval_code, aggregate, username, password, type):
    if etime == 'NOW':
        filter = "where ctime >= '%s'" % stime
    else:
        filter = "where '%s' <= ctime and ctime < '%s'" % (stime, etime)

    filter += hosttype_filter_string(type, True)

    query1 = system_sql('system_history', filter, interval_code, aggregate)
    query2 = system_sql('system_tail', filter, interval_code, aggregate)
    query = '%s union all %s' % (query1, query2)

    rows = execute_query(query, username, password)
    
    if aggregate == 'yes':
        return _system_consolidate_aggregate(rows)
    else:
        return _system_consolidate_nonaggregate(rows)

def diskspace_usage(stime, etime, username, password, type, interval_code, instance_name, now, summary, format):
    '''
        Purpose: Return a list of tuples containing the diskspace usage data either as an aggregated result from all
                 the hosts that has the same hosttype or from a single host, based on the summary field that is passed
                 in as a parameter.

        Returns: List of tuples(tkeys, hkeys, tab)
    '''
    rows_list = []; units = ''; filter = ''
    if type == 'all':
        (rows1, units) = diskspace_usage(stime, etime, username, password, 'gpdb', interval_code, instance_name, now, summary, format=False)
        (rows2, units) = diskspace_usage(stime, etime, username, password, 'hadoop', interval_code, instance_name, now, summary, format=False)
        (rows3, units) = diskspace_usage(stime, etime, username, password, 'etl', interval_code, instance_name, now, summary, format=False)
        if rows1:
           rows_list.append(rows1)
        if rows2:
           rows_list.append(rows2)
        if rows3:
           rows_list.append(rows3)
    elif type == 'hdw' or type == 'hdm' or type == 'hdc' or type == 'hbw' or type =='hadoop':
        filter = "where (filesystem IN ('/data', '/data1', '/data2', '/data3', '/data4', '/data5', '/data6', '/data7', '/data8', '/data9', '/data10', '/data11', '/data12'))"
    elif type == 'etl' or type == 'dia':
        filter = "where (filesystem IN ('/data', '/data1', '/data2'))"

    
    if now and type != 'all':
        table = 'diskspace_history'
        (query, units) = diskspace_sql(table, filter, now, interval_code, type, summary, instance_name)
    elif type != 'all': 
        filter += " and '%s' <= ctime and ctime < '%s'" % (stime, etime)
        (query1, units) = diskspace_sql('diskspace_history', filter, now, interval_code, type, summary, instance_name)
        (query2, units) = diskspace_sql('diskspace_tail', filter, now, interval_code, type, summary, instance_name)
        query = '%s union all %s' % (query1, query2)

    if type != 'all':
        rows = execute_query(query, username, password)

    if not format:
        return (rows, units)
    
    if summary: 
        if type == 'all':
            return _diskspace_summary_render(rows_list, type, units)
        else:
            return _diskspace_summary_render(rows, type, units)
    else:
        if type == 'all':
            return _diskspace_history_render(username, password, rows_list, type, instance_name, units)
        else:
            return _diskspace_history_render(username, password, rows, type, instance_name, units)


def diskspace_sql(table, filter, now, interval_code, type, summary, instance_name):

    '''
        Purpose: Helper function that is used by the diskspace_usage method
        which executes the sql query and returns the result.
        Returns: List of dictionary representing set of rows.
    '''

    units = 'GB'

    query_fragment = ""
    filter_type = filter_type_map[type]
    gpdbNode = True
    if type == 'hdw' or type == 'hdm' or type == 'hdc' or type == 'hbw' or type == 'etl' or type == 'dia' or type == 'hadoop':
        query_fragment = NONGPDB_DISK_SPACE_USAGE_SQL % (instance_name, filter_type)
        gpdbNode = False
    else:
        query_fragment = GPDB_DISK_SPACE_USAGE_SQL % (instance_name, filter_type)
    if summary:
        return (query_fragment, units)

    # Not summary && is now:
    if now:
        if gpdbNode:
            query_fragment = NO_SUMMARY_WRAP_GPDB % query_fragment
        else:
            query_fragment = NO_SUMMARY_WRAP % query_fragment
        return (query_fragment, units)
    # Not summary && not now:
    columns = [ 'total_bytes',  'bytes_used', 'bytes_available']
    itvl_sql = ["date_trunc('minute', ctime)",
                "date_trunc('hour', ctime)+(((trunc(date_part('minute', ctime)/5)*5)::text||' minutes')::interval)",
                "date_trunc('hour', ctime)",
                "date_trunc('day', ctime)+(((trunc(date_part('hour', ctime)/6)*6)::text||' hours')::interval)",
                "date_trunc('day', ctime)",
                "date_trunc('week', ctime)",
                "date_trunc('year', ctime)+(((trunc(date_part('month', ctime)/6)*6)::text||' months')::interval)",
                "ctime"]
    scaling = [ 1073741824, 1073741824, 1073741824]
    if type == 'hdw' or type == 'hdm' or type == 'hdc' or type == 'hbw' or type == 'etl' or type == 'dia' or type == 'hadoop':
        query_fragment = "select T.sample_time, count(distinct(T.hostname)) as hosts_current, hosttype as hostname"
        for i in range(len(columns)):
            query_fragment += ", round((sum(T.%s)::real/%s)::numeric, 2) as %s" % (columns[i], scaling[i], columns[i])
        query_fragment += " from ("
        query_fragment += " select %s as sample_time, hostname" %(itvl_sql[interval_code])
        for i in range(len(columns)):
            query_fragment += ", avg(%s) as %s" % (columns[i], columns[i])
        query_fragment += " from %s %s" % (table, filter)
        query_fragment += " group by %s.hostname, sample_time) as T, %s.dca_hostmapping s" % (table, instance_name)
        query_fragment += " where hostname = customerhostname "
        query_fragment += hosttypemapping_filter_string(type, True)
        query_fragment += " group by sample_time, hosttype" 
    else:
        query_fragment = "select sample_time, count(distinct(hostname)) as hosts_current, hosttype as hostname, oid"
        for i in range(len(columns)):
            query_fragment += ", round((sum(%s)::real/%s)::numeric, 2) as %s" % (columns[i], scaling[i], columns[i])
        query_fragment += " from (select %s as sample_time, dh.hostname, oid"  %(itvl_sql[interval_code])
        for i in range(len(columns)):
            query_fragment += ", avg(%s) as %s" % (columns[i], columns[i])
        query_fragment += " from %s dh, %s.fsmapcache fs" % (table, instance_name)
        query_fragment += " where dh.hostname =  host and mount = filesystem %s" %(filter)
        query_fragment += " group by hostname, sample_time, oid) ds ,"
        query_fragment += " (select distinct(hostname) as customerhostname, case content when -1 then 'master' else 'sdw' end as hosttype"
        query_fragment += " from gp_segment_configuration group by hostname, content) gseg"
        query_fragment += " where ds.hostname = gseg.customerhostname "
        query_fragment += hosttypemapping_filter_string(type, True)
        query_fragment += " group by sample_time, hosttype, oid"
    return (query_fragment, units)

def _diskspace_summary_render(rows, type, units):
    '''
        Purpose: Helper function currently used by the diskspace_usage method that formats the rows that is given as an input
                 into various dictionaries with key value pair. Also adds 'units' as an additional column to the input rows.

        Returns: tuples (tkeys, hkeys, ckeys, fkeys, tab)
    '''

    td = {}   #time dimension
    hd = {}   #host dimension
    fd = {}   #filesystem dimension
    tab = {}  #table where the key is composed of host and time

    x = None; uni={}
    if type == 'all':
        for i, row in enumerate(rows):
            for r in row:
                (h, t, f) = (r['hostname'], r['sample_time'], r['filesystem'])
                fd[f] = 1; hd[h] = 1; td[t] = 1
                uni['units'] = units
                r.update(uni)
                tab[(h,f)] = r
                x = r

    else:
        for r in rows:
            (h, t, f) = (r['hostname'], r['sample_time'], r['filesystem'])
            fd[f] = 1; hd[h] = 1; td[t] = 1
            uni['units'] = units
            r.update(uni)
            tab[(h,f)] = r
            x = r
    
    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = filter(lambda i: i != 'hostname' and i != 'host_count', x.keys())
        ckeys.sort()
    
    tkeys = td.keys()
    tkeys.sort()
    hkeys = hd.keys()
    hkeys.sort()
    fkeys = fd.keys()
    fkeys.sort()
    
    return (tkeys, hkeys, ckeys, fkeys, tab)



def _diskspace_history_render(username, password, rows, type, instance_name, units):
    ''' 
        Purpose: Helper function currently used by the diskspace_usage method that formats the rows that is given as an input
                 into various dictionaries with key value pair. Also adds 'display_name', 'hosts_total' and 'units' as additional
                 columns to the input rows.

        Returns: tuples (tkeys, hkeys, ckeys, fkeys, tab)
    '''
    td = {}   #time dimension
    hd = {}   #host dimension
    tab = {}  #table where the key is composed of host and time

    x = None
    total_hostcount = 0

    query = 'select count(distinct(dcahostname)) from %s.dca_hostmapping' % instance_name
    query += " where (dcahostname like 'hdw%')"
    res = execute_query(query, username, password)
    total_hdw_hostcount = res[0]['count']

    query = 'select count(distinct(dcahostname)) from %s.dca_hostmapping' % instance_name
    query += " where (dcahostname like 'hdm%')"
    res = execute_query(query, username, password)
    total_hdm_hostcount = res[0]['count']

    query = 'select count(distinct(dcahostname)) from %s.dca_hostmapping' % instance_name
    query += " where (dcahostname like 'hdc%')"
    res = execute_query(query, username, password)
    total_hdc_hostcount = res[0]['count']

    query = 'select count(distinct(dcahostname)) from %s.dca_hostmapping' % instance_name
    query += " where (dcahostname like 'hbw%')"
    res = execute_query(query, username, password)
    total_hbw_hostcount = res[0]['count']

    query = 'select count(distinct(dcahostname)) from %s.dca_hostmapping' % instance_name
    query += " where (dcahostname like 'etl%')"
    res = execute_query(query, username, password)
    total_dia_hostcount = res[0]['count']

    query = 'select count(distinct(hostname)) from gp_segment_configuration'
    query += " where (hostname like 'sdw%')"
    res = execute_query(query, username, password)
    total_sdw_hostcount = res[0]['count']

    query = 'select count(distinct(hostname)) from gp_segment_configuration'
    query += " where (hostname like '%mdw')"
    res = execute_query(query, username, password)
    total_master_hostcount = res[0]['count']

    if type == 'all':
        for i, row in enumerate(rows):
            for r in row:
                (h, t) = (r['hostname'], r['sample_time'])
                td[t] = 1; hd[h] = 1;
                thc = {}; uni = {}
                if h == 'hdw':
                    d = {'display_name': 'Hadoop Worker'}
                    thc['hosts_total'] = total_hdw_hostcount
                elif h == 'hdm':
                    d = {'display_name': 'Hadoop Master'}
                    thc['hosts_total'] = total_hdm_hostcount
                elif h == 'hdc':
                    d = {'display_name': 'Hadoop Compute'}
                    thc['hosts_total'] = total_hdc_hostcount
                elif h == 'hbw':
                    d = {'display_name': 'HBase Worker'}
                    thc['hosts_total'] = total_hdc_hostcount
                elif h == 'master':
                    d = {'display_name': 'GP Master'} 
                    thc['hosts_total'] = total_master_hostcount
                elif h == 'sdw':
                    d = {'display_name': 'GP Segments'}
                    thc['hosts_total'] = total_sdw_hostcount
                elif h == 'etl':
                    d = {'display_name': 'ETL'}
                    thc['hosts_total'] = total_dia_hostcount
                elif h == 'dia':
                    d = {'display_name': 'ETL'}
                    thc['hosts_total'] = total_dia_hostcount
                else:
                    d = {'display_name': 'Invalid'}
                uni['units'] = units
                r.update(d)
                r.update(thc)
                r.update(uni)
                tab[(h,t)] = r
                x = r 
    else:       
        for r in rows:
            (h, t) = (r['hostname'], r['sample_time'])
            td[t] = 1; hd[h] = 1;
            thc = {}; uni = {}
            if h == 'hdw':
                d = {'display_name': 'Hadoop Worker'}
                thc['hosts_total'] = total_hdw_hostcount
            elif h == 'hdm':
                d = {'display_name': 'Hadoop Master'}
                thc['hosts_total'] = total_hdm_hostcount
            elif h == 'hdc':
                d = {'display_name': 'Hadoop Compute'}
                thc['hosts_total'] = total_hdc_hostcount
            elif h == 'hbw':
                d = {'display_name': 'HBase Worker'}
                thc['hosts_total'] = total_hbw_hostcount
            elif h == 'master':
                d = {'display_name': 'GP Master'} 
                thc['hosts_total'] = total_master_hostcount
            elif h == 'sdw':
                d = {'display_name': 'GP Segments'}
                thc['hosts_total'] = total_sdw_hostcount
            elif h == 'etl':
                d = {'display_name': 'ETL'}
                thc['hosts_total'] = total_dia_hostcount
            elif h == 'dia':
                d = {'display_name': 'ETL'}
                thc['hosts_total'] = total_dia_hostcount
            else:
                d = {'display_name': 'Invalid'}
            uni['units'] = units
            r.update(d)
            r.update(thc)
            r.update(uni)
            tab[(h,t)] = r
            x = r 

    # retrieve the column names into ckeys
    ckeys = None
    if x:
        ckeys = filter(lambda i: i != 'hostname', x.keys())
        ckeys.sort()

    tkeys = td.keys()
    tkeys.sort()
    hkeys = hd.keys()
    hkeys.sort()
    return (tkeys, hkeys, ckeys, tab)


def queries_now(remte, status, username, database, textlength, dbuser, dbpass):
    filter = ''
    if status != '':
        status_list = (', '.join("'" + i + "'" for i in status))
        filter += " where status in (%s)" % status_list

    if username != '':
        if filter == '':
            filter = " where"
        else:
            filter += " and"
        filter += " username='%s'" % username

    if database != '':
        if filter == '':
            filter = " where"
        else:
            filter += " and"
        filter += " db='%s'" % database

    columns = queries_sql(textlength)
    
    # Additions for getting query priority and current queue name,  "N/A" will
    # be filled in when no priority or queuename can be determined
    columns += " , coalesce(rps.rqppriority, 'N/A') as priority, coalesce(rr.rrrsqname, 'N/A') as queuename "
    join = " left outer join gp_toolkit.gp_resq_priority_statement rps on (qn.ssid=rps.rqpsession and qn.ccnt=rps.rqpcommand) join gp_toolkit.gp_resq_role rr on (qn.username=rr.rrrolname)"

    query = '%s from queries_now qn %s %s' % (columns, join, filter)

    rows = queries_db(query, textlength, dbuser, dbpass)

    return _queries_consolidate(rows)


def queryText(tmid, ssid, ccnt):
    filename = "%s/q%s-%s-%s.txt" % (path, tmid, ssid, ccnt)

    try:
        q = open(filename, 'r')
    except:

        log.msg('could not open query text file: %s' % filename)
        # Changing this from exception to just return 'not available'
        #raise GPDBError, 'Real-time query_text file unavailable'
        return '[not available]'

    try:
        qtext = ''
        # skip the first line
        q.readline()
        for line in q:
            qtext += line.rstrip() + '\n'
    finally:
        q.close()

    return qtext.rstrip()[0:-1]


def queries_file(status, username, database, textlength, tmid, ssid, ccnt):
    filename = "%s/queries_now.dat" % path

    # ordering is important to match the order in the file
    cnames = [  'sample_time', 'tmid', 'ssid', 'ccnt',
                'username', 'db', 'cost', 'tsubmit', 
                'tstart', 'tfinish', 'status', 'rows_out', 
                'cpu_elapsed', 'cpu_currpct', 
                'skew_cpu', 'skew_rows', 
                'query_hash', 'query_text', 'query_plan' ]

    rows = []

    try:
        f = open(filename, 'r')
    except:
        log.msg('could not open queries_now file: %s' % filename)
        raise GPDBError, 'Real-time queries_now file unavailable'
        return ''

    try:
        for line in f:

            columns = {} # dict to contain the values of each column
            entry = line.split('|')
            # skip rows that do not belong to the owner if supplied
            if username != '' and username != entry[4]:
                continue
            # skip rows that do not match the database desired
            if database != '' and database != entry[5]:
                continue
            # skip rows that do have the status desired
            if status != '' and (entry[10] not in status):
                continue
            # check for tmid, ssid, ccnt
            if tmid != '' and tmid != entry[1]:
                continue
            if ssid != '' and ssid != entry[2]:
                continue
            if ccnt != '' and ccnt != entry[3]:
                continue
            # convert ctime date string into datetime object
            entry[0] = datetime.datetime.strptime(entry[0], "%Y-%m-%d %H:%M:%S")
            # convert tsubmit date string into datetime object
            entry[7] = datetime.datetime.strptime(entry[7], "%Y-%m-%d %H:%M:%S")
            # convert tstart date string into datetime object
            if entry[8] != 'null':
                entry[8] = datetime.datetime.strptime(entry[8], "%Y-%m-%d %H:%M:%S")
            # if the query hasn't completed, the ftin will be set to 'null'
            if entry[9] != 'null':
                # convert tfin date string into datetime object
                entry[9] = datetime.datetime.strptime(entry[9], "%Y-%m-%d %H:%M:%S")
            for i in range(len(cnames)):
                if cnames[i] == 'query_text':
                    _tmid = entry[1]
                    _ssid = entry[2]
                    _ccnt = entry[3]
                    entry[i] = queryText(_tmid, _ssid, _ccnt)
                    if textlength != '':
                        # truncate the query text
                        if textlength > 3 and len(entry[i]) > textlength:
                            entry[i] = entry[i][:textlength-3] + '...'
                columns[cnames[i]] = entry[i]
            rows.append(columns)
    finally:
        f.close()

    return rows


def queries_sql(textlength):
    columns = [ 'ctime as sample_time', 'tmid', 'ssid', 'ccnt',
                'username', 'db', 'cost', 'tsubmit', 
                'tstart', 'tfinish', 'status', 'rows_out', 
                'cpu_elapsed', 'cpu_currpct', 
                'skew_cpu', 'skew_rows', 
                'query_hash', 'query_plan' ]

    if textlength != '':
        query_fragment = "select length(query_text), substr(query_text, 0, %s) as query_text" % textlength
    else:
        query_fragment = "select query_text"

    for column in columns:
        query_fragment += ", %s" % column

    return query_fragment


def queries_history(status, stime, etime, username, runtime, database, textlength, max_query_limit, dbuser, dbpass):
    if etime == 'NOW':
        filter = "where '%s' <= tfinish" % stime
    else:
        filter = "where '%s' <= tfinish and tstart <= '%s'" % (stime, etime)

    if runtime != '':
        filter += " and (tfinish - tstart) >='%s'" % runtime

    if status != '':
        status_list = (', '.join("'" + i + "'" for i in status))
        filter += " and status in (%s)" % status_list

    if username != '':
        filter += " and username='%s'" % username

    if database != '':
        filter += " and db='%s'" % database

    columns = queries_sql(textlength)
    #Work around to fill in values for priority and Resource Queue name, 
    #since they currently cannot be determined for queries that have completed.
    columns += ", 'N/A' as priority, 'N/A' as queuename "

    query1 = '%s from queries_history %s' % (columns, filter)
    query2 = '%s from queries_tail %s' % (columns, filter)
    query = "(%s) union all (%s) limit %s" % (query1, query2, max_query_limit)

    rows = queries_db(query, textlength, dbuser, dbpass)

    return _queries_consolidate(rows)


def queries_db(query, textlength, username, password):
    rows = []
    try:
        for r in execute_query(query, username, password):
            if textlength != '':
                if r['length'] > textlength:
                    if textlength > 3:
                        r['query_text'] = r['query_text'][:textlength-3] + '...'
            rows.append(r)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def querydetails_now(remote, tmid, ssid, ccnt, username, dbuser, dbpass):
    columns = queries_sql('')

    filter = "where tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)
    if username != '':
        filter += " and username='%s'" % username

    # Additions for getting query priority and current queue name,  "N/A" will
    # be filled in when no priority or queuename can be determined
    columns += " , coalesce(rps.rqppriority, 'N/A') as priority, coalesce(rr.rrrsqname, 'N/A') as queuename "
    join = " left outer join gp_toolkit.gp_resq_priority_statement rps on (qn.ssid=rps.rqpsession and qn.ccnt=rps.rqpcommand) join gp_toolkit.gp_resq_role rr on (qn.username=rr.rrrolname)"

    query = '%s from queries_now qn %s %s' % (columns, join, filter)

    rows = execute_query(query, dbuser, dbpass)
    
    return _queries_consolidate(rows)


def querydetails_history(tmid, ssid, ccnt, username, start, end, dbuser, dbpass):
    columns = queries_sql('')

    filter = "where tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)
    if username != '':
        filter += " and username='%s'" % username
    if start != '' and end != '':
        filter += " and ctime>='%s' and ctime<='%s'" % (start, end)
        
    #Work around to fill in values for priority and Resource Queue name, 
    #since they currently cannot be determined for queries that have completed.
    columns += ", 'N/A' as priority, 'N/A' as queuename "
    
    query1 = '%s from queries_history %s' % (columns, filter)
    query2 = '%s from queries_tail %s' % (columns, filter)
    query = "(%s) union all (%s) limit 1" % (query1, query2)

    rows = execute_query(query, dbuser, dbpass)

    return _queries_consolidate(rows)



def queryplan_get_username_now(tmid, ssid, ccnt, username, password):
    query_fragment = "select username"
    filter = "where tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)
    query = "%s from queries_now %s limit 1" % (query_fragment, filter)
    
    result = ''
    try:
        r = execute_single_value_query(query, username, password)
        result = '%s' % r
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return result


# return [gpdbUptime, gpdbVersion, openConnections, serverTime, dcaVersion]
def get_uptime(username, password, isAppliance, instance_name):

    results = ["", "", "", "", "", ""]
    queries = [ "select to_char(pg_postmaster_start_time(), 'YYYY-MM-DD HH24:MI:SS TZ');", 
                "select version();", 
                "select count(*) - 1 from pg_stat_activity;",
                "select to_char(now(), 'YYYY-MM-DD HH24:MI:SS TZ')"]

    if isAppliance:
        queries.append("select * from %s.dca_appliance_version;" % instance_name)
        queries.append("select * from %s.dca_serial_number;" % instance_name)

    for i in range(len(queries)):
        try:
            results[i] = execute_single_value_query(queries[i], username, password)
        except Exception, e:
            log.msg(e.__str__())
            log.msg('error during query: %s' % queries[i])
        except:
            log.msg('error during query: %s' % queries[i])

    return results

 
def queryplan_sql(table, tmid, ssid, ccnt, start='', end=''):
    query = """select
       min(ctime) as sample_time, tmid, ssid, ccnt, nid, min(pnid) as pnid,
       min(ntype) as ntype, array_to_string(iterators_array_accum(distinct nstatus), ',') as nstatus,
       min(tstart) as tstart, avg(tduration) as tduration,
       avg(pmemsize) as pmemsize, avg(pmemmax) as pmemmax,
       avg(memsize) as memsize, avg(memresid) as memresid,
       avg(memshare) as memshare, avg(cpu_elapsed) as cpu_elapsed,
       avg(cpu_currpct) as cpu_currpct, array_to_string(iterators_array_accum(distinct phase), ',') as phase, 
       sum(rows_out) as rows_out, sum(rows_out_est) as rows_out_est,
       case when avg(cpu_elapsed) <= 0.001 THEN 0 else
          (stddev(cpu_elapsed)/avg(cpu_elapsed))*100 end as skew_cpu,
       case when avg(rows_out) <= 0.001 THEN 0 else
          (stddev(rows_out)/avg(rows_out))*100 end as skew_rows,
       min(m0_name)||'|'||min(m0_unit)||'|'||avg(m0_val)||'|'||avg(m0_est) as m0,
       min(m1_name)||'|'||min(m1_unit)||'|'||avg(m1_val)||'|'||avg(m1_est) as m1,
       min(m2_name)||'|'||min(m2_unit)||'|'||avg(m2_val)||'|'||avg(m2_est) as m2,
       min(m3_name)||'|'||min(m3_unit)||'|'||avg(m3_val)||'|'||avg(m3_est) as m3,
       min(m4_name)||'|'||min(m4_unit)||'|'||avg(m4_val)||'|'||avg(m4_est) as m4,
       min(m5_name)||'|'||min(m5_unit)||'|'||avg(m5_val)||'|'||avg(m5_est) as m5,
       min(m6_name)||'|'||min(m6_unit)||'|'||avg(m6_val)||'|'||avg(m6_est) as m6,
       min(m7_name)||'|'||min(m7_unit)||'|'||avg(m7_val)||'|'||avg(m7_est) as m7,
       min(m8_name)||'|'||min(m8_unit)||'|'||avg(m8_val)||'|'||avg(m8_est) as m8,
       min(m9_name)||'|'||min(m9_unit)||'|'||avg(m9_val)||'|'||avg(m9_est) as m9,
       min(m10_name)||'|'||min(m10_unit)||'|'||avg(m10_val)||'|'||avg(m10_est) as m10,
       min(m11_name)||'|'||min(m11_unit)||'|'||avg(m11_val)||'|'||avg(m11_est) as m11,
       min(m12_name)||'|'||min(m12_unit)||'|'||avg(m12_val)||'|'||avg(m12_est) as m12,
       min(m13_name)||'|'||min(m13_unit)||'|'||avg(m13_val)||'|'||avg(m13_est) as m13,
       min(m14_name)||'|'||min(m14_unit)||'|'||avg(m14_val)||'|'||avg(m14_est) as m14,
       min(m15_name)||'|'||min(m15_unit)||'|'||avg(m15_val)||'|'||avg(m15_est) as m15,
       min(t0_name)||'|'||min(t0_val) as t0
       from %s""" % table
    query += "\nwhere tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)
    if start != '' and end != '':
        query += " and ctime>='%s' and ctime<='%s'" % (start, end)
    query += "\ngroup by tmid, ssid, ccnt, nid"

    return query


def queryplan_now(tmid, ssid, ccnt, username, dbuser, dbpass):
    # If not superuser, check that username matches
    if username != '':
        q_username = queryplan_get_username_now(tmid, ssid, ccnt, dbuser, dbpass)
        if q_username != username:
            return _queryplan_consolidate(rows)
            
    query1 = queryplan_sql("iterators_now", tmid, ssid, ccnt)
    query = query1 + " order by pnid, nid"

    rows = execute_query(query, dbuser, dbpass)

    return _queryplan_consolidate(rows)


def queryexplain(tmid, ssid, ccnt, sessionuser, sessionpass, realtime, start = '', end = ''):
    # Get query info include query_text, dbname, using 'gpmon'
    filter = "where tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)

    if realtime == 'yes':
        query = 'select db, query_text from queries_now %s limit 1' % filter
        row = execute_query(query, pguser, pgpass, database = pgdatabase)
        # query may locate in queries_tail table
        if len(row) == 0:
            query = 'select db, query_text from queries_tail %s limit 1' % filter
            row = execute_query(query, pguser, pgpass, database = pgdatabase)
        # query may locate in recent queries_history table
        if len(row) == 0:
            start = datetime.datetime.now() - datetime.timedelta(minutes = 10)
            start = start.strftime("%Y-%m-%d %H:%M:%S")
            filter += " and ctime>='%s'" % (start)
            query = 'select db, query_text from queries_history %s limit 1' % filter
            row = execute_query(query, pguser, pgpass, database = pgdatabase)
    else:
        if start != '':
            filter += " and ctime>='%s'" % (start)
        if end != '':
            filter += " and ctime<='%s'" % (end)
        query = 'select db, query_text from queries_history %s limit 1' % filter
        row = execute_query(query, pguser, pgpass, database = pgdatabase)

    if not row :
        return []
    elif len(row) != 1:
        raise_db_error('Unexpected error: %s-%s-%s is not exclusive' % (tmid, ssid, ccnt))

    query_text = row[0]['query_text']
    dbname = row[0]['db']

    # Get query explain result using sessionuser, if has no privilege, a db error will be raised
    explain_query = "explain %s"%query_text
    results = execute_query(explain_query, sessionuser, sessionpass, database = dbname)
    return results

def queryplan_get_username_history(tmid, ssid, ccnt, start, end, username, password):
    query_fragment = "select username"
    filter = "where tmid='%s' and ssid='%s' and ccnt='%s'" % (tmid, ssid, ccnt)
    if start != '' and end != '':
        filter += " and ctime>='%s' and ctime<='%s'" % (start, end)
    query1 = "%s from queries_history %s" % (query_fragment, filter)
    query2 = "%s from queries_tail %s" % (query_fragment, filter)
    query = "(%s) union all (%s) limit 1" % (query1, query2)
    
    result = ''
    try:
        r = execute_single_value_query(query, username, password)
        result = '%s' % r
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return result


def queryplan_history(tmid, ssid, ccnt, username, start, end, dbuser, dbpass):
    # If not superuser, check that username matches
    if username != '':
        q_username = queryplan_get_username_history(tmid, ssid, ccnt, start, end, dbuser, dbpass)
        if q_username != username:
            return _queryplan_consolidate(rows)
            
    query1 = queryplan_sql("iterators_history", tmid, ssid, ccnt, start, end)
    query2 = queryplan_sql("iterators_tail", tmid, ssid, ccnt)
    query = "(%s) union all (%s) order by pnid, nid" % (query1, query2)

    rows = execute_query(query, dbuser, dbpass)

    return _queryplan_consolidate(rows)


def rt_queryiterators(tmid, ssid, ccnt, segid='', nid=''):
    filename = "%s/iterators_now.dat" % path

    # ordering is important to match the order in the file
    cnames = [  'ctime', 'tmid', 'ssid', 'ccnt', 'segid',
                'pid', 'nid', 'pnid', 'hostname', 'ntype',
                'nstatus', 'tstart', 'tduration', 'pmemsize',
                'pmemmax', 'memsize', 'memresid', 'memshare',
                'cpu_elapsed', 'cpu_currpct', 'phase', 
                'rowsout', 'rowsout_est',
                'm0_name', 'm0_unit', 'm0_val', 'm0_est',
                'm1_name', 'm1_unit', 'm1_val', 'm1_est',
                'm2_name', 'm2_unit', 'm2_val', 'm2_est',
                'm3_name', 'm3_unit', 'm3_val', 'm3_est',
                'm4_name', 'm4_unit', 'm4_val', 'm4_est',
                'm5_name', 'm5_unit', 'm5_val', 'm5_est',
                'm6_name', 'm6_unit', 'm6_val', 'm6_est',
                'm7_name', 'm7_unit', 'm7_val', 'm7_est',
                'm8_name', 'm8_unit', 'm8_val', 'm8_est',
                'm9_name', 'm9_unit', 'm9_val', 'm9_est',
                'm10_name', 'm10_unit', 'm10_val', 'm10_est',
                'm11_name', 'm11_unit', 'm11_val', 'm11_est',
                'm12_name', 'm12_unit', 'm12_val', 'm12_est',
                'm13_name', 'm13_unit', 'm13_val', 'm13_est',
                'm14_name', 'm14_unit', 'm14_val', 'm14_est',
                'm15_name', 'm15_unit', 'm15_val', 'm15_est',
                't0_name', 't0_val' ]

    rows = []
    try:
        f = open(filename, 'r')
    except:
        log.msg('could not open iterators_now file: %s' % filename)
        raise GPDBError, 'Real-time iterators_now file unavailable'
        return ''

    try:
        for line in f:

            columns = {} # dict to contain the values of each column
            entry = line.split('|')
            # positional matching. if cnames is modified, the index
            # might be affected.
            if entry[1] != tmid:
                continue
            # positional matching. if cnames is modified, the index
            # might be affected.
            elif entry[2] != ssid:
                continue
            # positional matching. if cnames is modified, the index
            # might be affected.
            elif entry[3] != ccnt:
                continue
            # positional matching. if cnames is modified, the index
            # might be affected.
            elif segid != '' and entry[4] != segid:
                continue
            # positional matching. if cnames is modified, the index
            # might be affected.
            elif nid != '' and entry[6] != nid:
                continue
            # convert ctime date string into datetime object
            entry[0] = datetime.datetime.strptime(entry[0], "%Y-%m-%d %H:%M:%S")
            # convert tstart date string into datetime object
            entry[11] = datetime.datetime.strptime(entry[11], "%Y-%m-%d %H:%M:%S")
            for i in range(len(cnames)):
                # do not include the pid if searching based on node id (nid)
                if nid != '' and cnames[i] == 'pid':
                    continue
                columns[cnames[i]] = entry[i]
            rows.append(columns)
    finally:
        f.close()

    return rows



def iterator_sql():
    columns = [ 'segid', 'ntype', 'nstatus', 'tstart', 'tduration',
                'pmemsize', 'pmemmax', 'memsize', 'memresid', 'memshare',
                'cpu_elapsed', 'cpu_currpct', 'phase',
                'rowsout', 'rowsout_est',
                'm0_name', 'm0_unit', 'm0_val', 'm0_est',
                'm1_name', 'm1_unit', 'm1_val', 'm1_est',
                'm2_name', 'm2_unit', 'm2_val', 'm2_est',
                'm3_name', 'm3_unit', 'm3_val', 'm3_est',
                'm4_name', 'm4_unit', 'm4_val', 'm4_est',
                'm5_name', 'm5_unit', 'm5_val', 'm5_est',
                'm6_name', 'm6_unit', 'm6_val', 'm6_est',
                'm7_name', 'm7_unit', 'm7_val', 'm7_est',
                'm8_name', 'm8_unit', 'm8_val', 'm8_est',
                'm9_name', 'm9_unit', 'm9_val', 'm9_est',
                'm10_name', 'm10_unit', 'm10_val', 'm10_est',
                'm11_name', 'm11_unit', 'm11_val', 'm11_est',
                'm12_name', 'm12_unit', 'm12_val', 'm12_est',
                'm13_name', 'm13_unit', 'm13_val', 'm13_est',
                'm14_name', 'm14_unit', 'm14_val', 'm14_est',
                'm15_name', 'm15_unit', 'm15_val', 'm15_est',
                't0_name', 't0_val' ]

    query_fragment = "select ctime"
    for column in columns:
        query_fragment += ", %s" % column

    return query_fragment


# returns iterator data across all segments.
def queryiterator(tmid, ssid, ccnt, nid, dbuser, dbpass):
    query_fragment = iterator_sql()
    filter = "where tmid='%s' and ssid='%s' and ccnt='%s' and nid='%s'" % (tmid, ssid, ccnt, nid)

    query1 = "%s from iterators_history %s" % (query_fragment, filter)
    query2 = "%s from iterators_tail %s" % (query_fragment, filter)
    query = "%s\nunion all\n%s" % (query1, query2)

    rows = execute_query(query, dbuser, dbpass)

    # query real-time information.
    segid = ''
    for r in rt_queryiterators(tmid, ssid, ccnt, segid, nid):
        rows.append(r)

    return _iterator_consolidate(rows)



def database_now(remote, dbuser, dbpass):
    if remote:
        interval_code = 7
        query = database_sql('database_now', '', interval_code)
        rows = execute_query(query, dbuser, dbpass)
    else:
        rows = database_file()

    return _database_consolidate(rows)


def database_file():
    filename = "%s/database_now.dat" % path

    # ordering is important to match the order in the file
    cnames = [  'sample_time', 'queries_total', 
                'queries_running', 'queries_queued']

    rows = []

    try:
        f = open(filename, 'r')
    except:
        log.msg('could not open database_now file: %s' % filename)
        raise GPDBError, 'Real-time database_now file unavailable'
        return ''

    try:
        for line in f:
            columns = {} # dict to contain the values of each column
            entry = line.split('|')
            # convert date string into datetime object
            entry[0] = datetime.datetime.strptime(entry[0], "%Y-%m-%d %H:%M:%S")
            # append realtime data to the end of the array
            for i in range(len(cnames)):
                columns[cnames[i]] = entry[i]
            rows.append(columns)
    finally:
        f.close()

    return rows


def database_sql(table, filter, interval_code):
    columns = ['queries_total', 'queries_running', 'queries_queued']

    # Time aggregation expressions for each level of aggregration
    #  1min, 5min, 1hr, 6hr, 1day, 1wk, 6mth
    itvl_sql = ["date_trunc('minute', ctime)",
                "date_trunc('hour', ctime)+(((trunc(date_part('minute', ctime)/5)*5)::text||' minutes')::interval)",
                "date_trunc('hour', ctime)",
                "date_trunc('day', ctime)+(((trunc(date_part('hour', ctime)/6)*6)::text||' hours')::interval)",
                "date_trunc('day', ctime)",
                "date_trunc('week', ctime)",
                "date_trunc('year', ctime)+(((trunc(date_part('month', ctime)/6)*6)::text||' months')::interval)",
                "ctime"]


    query_fragment = "select %s as sample_time" % itvl_sql[interval_code]
    for column in columns:
        query_fragment += ", avg(%s) as %s" % (column, column)
        if interval_code != 7:
            query_fragment += ", min(%s) as %s_min" % (column, column)
            query_fragment += ", max(%s) as %s_max" % (column, column)

    query_fragment += " from %s %s" % (table, filter)
    query_fragment += " group by sample_time"
    return query_fragment


def database_history(stime, etime, interval_code, dbuser, dbpass):
    if etime == 'NOW':
        filter = "where ctime >= '%s'" % stime
    else:
        filter = "where '%s' <= ctime and ctime < '%s'" % (stime, etime)

    query1 = database_sql('database_history', filter, interval_code)
    query2 = database_sql('database_tail', filter, interval_code)
    query = '%s union all %s' % (query1, query2)

    rows = execute_query(query, dbuser, dbpass)

    return _database_consolidate(rows)


def database_state(dbuser, dbpass, auth):
    '''
    Validate database state with following tests:
        1. Can we connect (db up, valid password)
        2. What mode is the database in (normal, upgrade, master only, etc...)
        3. Are segments in primary role
        4. Are mirrors in sync
    '''
    global auth_mech
    auth_mech = auth
    dbstatus_normal = 'NORMAL'
    dbstatus_degraded = 'DEGRADED'
    dbstatus_down = 'DOWN'
    dbstatus_unbalanced = 'UNBALANCED'
    dbstatus_upgrade = 'UPGRADE'
    dbstatus_maintenance = 'MAINTENANCE'
    dbstatus_masteronly = 'MASTER_ONLY'
    dbstatus_auth = 'AUTH_ERROR'
    dbstatus_sqlerr = 'SQL_ERROR'
    dbstatus_unknown = 'UNKNOWN'

    # are any segments not syncronized 
    degradeState_query =  "select count(*) from gp_segment_configuration where mode <> 's'"
    # are any segdb's not in prefered role
    unbalancedState_query = "select count(*) from gp_segment_configuration where role <> preferred_role"

    # try to connect and translate exception error msg (if one is returned)
    log.debug('Testing connection to %s on port %s' % (pgdatabase, pgport))
    try:
        if auth_mech == 'krb' :
            conn = pg.connect(dbname=pgdatabase, host=pghost, port=pgport, user=dbuser)
        else :
            conn = pg.connect(dbname=pgdatabase, host=pghost, port=pgport, user=pguser)
            
    except pg.InternalError, err:
        log.msg('connect exception: %s' % sys.exc_info()[1])
        clearKerberos()
        msg = '%s' % err
        # check msg from exception to see why db not accepting connection
        if 'master-only utility mode' in msg:
            log.msg('database %s, port %s, on host %s in utility mode' % (pgdatabase, pgport, pghost) )
            return dbstatus_masteronly

        if 'Connection refused' in msg:
            log.msg('database %s, port %s, on host %s not accepting connections (down)' % (pgdatabase, pgport, pghost) )
            return dbstatus_down

        if 'password authentication failed' in msg:
            log.msg('Invalid password provided for %s. Database %s, port %s, host %s' % (pguser, pgdatabase, pgport, pghost) )
            return dbstatus_auth

        if 'Upgrade in progress' in msg:
            log.msg('database %s, port %s, on host %s is being upgraded' % (pgdatabase, pgport, pghost) )
            return dbstatus_upgrade

        if 'AL:  Maintenance mode' in msg:
            log.msg('database %s, port %s, on host %s in maintenance mode' % (pgdatabase, pgport, pghost) )
            return dbstatus_maintenance

        log.msg('Conn exception: %s' % sys.exc_info()[1])
        return dbstatus_unknown
    except TypeError, err:
        clearKerberos()
        log.msg('bad arg (or too many args) in call to pg.connect')
        return dbstatus_unknown
    except SyntaxError, err:
        clearKerberos()
        log.msg('Synatx error in call to pg.connect.  You should _never_ see this')
        return dbstatus_unknown
    except:
        clearKerberos()
        log.msg( 'Unxpected error in connection to database %s, port %s, host %, user %s' % (pgdatabase, pgport, pghost, pguser) )
        log.msg( '%s' % sys.exc_info()[1] )
        return dbstatus_unknown

    # query db to see if any segs are not synced or in preferred role
    try:
        query = conn.query( degradeState_query )
        res = query.dictresult()
        if res[0]['count'] != 0:
            return dbstatus_degraded

        query = conn.query( unbalancedState_query )
        res = query.dictresult()
        if res[0]['count'] != 0:
            return dbstatus_unbalanced
    except Exception, e:
        log.msg('error connecting to GPDB: %s for query: %s' % (e.__str__().strip(), unbalancedState_query))
        log.msg("dbname=%s, host=%s, port=%s, user=%s" % (pgdatabase, pghost, pgport, dbuser))
        return dbstatus_sqlerr
    except:
        log.msg('error connecting to GPDB for query: %s' % (query))
        log.msg("dbname=%s, host=%s, port=%s, user=%s" % (pgdatabase, pghost, pgport, dbuser))
        return dbstatus_sqlerr

    conn.close()  # don't leak those connections
    return dbstatus_normal

def readLastUpdateTimeForHealthFromDisk():
    retval = 0
    filename = "%s/snmp/lastreport.txt" % (path)
    try:
        f = open(filename, 'r')
    except:
        return 0

    try:
        for line in f:
            line = line.strip()
            cols = line.split("|")
            if len(cols) == 2:
                retval = int(cols[1])
            break
    finally:
        f.close()

    return retval

class HealthInfo:
    def __init__(self):
        self.lastreadfromdisk = 0
        self.updatetime = 0
        self.table = None # hash (k: categories v: list) ... each item in list is a tuple (hostname, status)
        self.deviceStatus = None  # hash: k: host/device name, v: status   Example: {'sdw1':'normal', 'sdwd2':'unreachable'}

cachedHealthInfo = HealthInfo() 

def health():

    # cache values for 10 seconds to avoid repeated access to filesystem
    if (time.time() - cachedHealthInfo.lastreadfromdisk) > 10:
        cachedHealthInfo.lastreadfromdisk = time.time()
        cachedHealthInfo.updatetime = readLastUpdateTimeForHealthFromDisk()
        cachedHealthInfo.table = dict()
        cachedHealthInfo.deviceStatus = dict()

        filename = "%s/snmp/hostlistreport.txt" % (path)
        try:
            f = open(filename, 'r')
        except:
            log.msg('could not open health file: %s' % filename)
            raise GPDBError, 'health data unavailable'

        try:
            for line in f:
                line = line.strip()
                cols = line.split("|")
                if len(cols) != 3:
                    continue
        
                category = cols[0]

                if category not in cachedHealthInfo.table:
                    cachedHealthInfo.table[category] = list()

                # add (hostname, status_
                cachedHealthInfo.table[category].append( (cols[1], cols[2]) )

                # add hostname/status to a simple dictionary
                cachedHealthInfo.deviceStatus[ cols[1] ] = cols[2]

        except Exception, e:
            log.msg('error reading from health file: %s' % filename)
            log.msg(e.__str__())
            raise GPDBError, 'health status unavailable'
        finally:
            f.close()

        cachedHealthInfo.lastreadfromdisk = time.time()

    return (cachedHealthInfo.updatetime, cachedHealthInfo.table)
    

def healthdetails(hostname):

    results = list()

    # early exit if host is not reachable
    if cachedHealthInfo.deviceStatus.has_key(hostname) and cachedHealthInfo.deviceStatus[ hostname ] == 'unreachable':
        cols = ['N/A', hostname, '1', '1', hostname, 'N/A', 'unreachable', 'Host, device, or service is unreachable or offline']
        results.append(cols)
        return results

    filename = "%s/snmp/snmp.host.%s.txt" % (path, hostname)
    try:
        f = open(filename, 'r')
    except:
        log.msg('could not open health details file: %s' % filename)
        raise GPDBError, 'health details for %s unavailable' % hostname
    
    try:
        for line in f:
            line = line.strip()
            cols = line.split("|")
            if len(cols) != 8:
                continue
            results.append(cols)
    except:
        log.msg('error reading from health details file: %s' % filename)
        raise GPDBError, 'health details for %s unavailable' % hostname
    finally:
        f.close()

    return results

def run_remote_command(hostname, cmdStr, getRetCode=None):
    remoteCmdStr = '%s %s "%s"' %(ssh_full_path, hostname, cmdStr)

    try:    
        p = subprocess.Popen(remoteCmdStr, shell=True, executable="/bin/bash", stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        output = p.communicate()
        if getRetCode:
            return p.returncode 
        if p.returncode != 0:
            log.msg('Error running command: %s returncode: %s \n stdout: %s\n stderr: %s' %(remoteCmdStr, str(p.returncode), output[0], output[1]))
            return None
        if output != None and output[0] != None:
            return output[0]
        else:
            return None

    except Exception, e:
        log.msg('Exception running cmd: %s: %s' % (remoteCmdStr, e.__str__()))
        return None

def run_command(cmdStr):

    try: 
        p = subprocess.Popen(cmdStr, shell=True, executable="/bin/bash")
        sts = os.waitpid(p.pid, 0)[1]
        if sts: 
            return False
        else:
            return True

    except Exception, e:
        log.msg("Exception running cmd: %s: %s" % (cmdStr, e.__str__()))
        return False
    except:
        log.msg("Exception running cmd: %s" % (cmdStr))
        return False

# Returns if healthmon is running on the master database
def is_health_data_stale(db_hostname, dbuser, dbpass):

    try:
        (major, minor, unused, unused) = getgpdb_numericversion(dbuser, dbpass)
        if major == 4 and minor == 0:
            return "NO"
    except Exception, e:
        raise_db_error("invaid GPDB version format: %s" % (e))

    # Find if the master where DB is hosted is mdw, or smdw
    cmd = "cat /etc/gpnode"
    host = run_remote_command(db_hostname, cmd)
    if host == None or len(host) == 0:
        log.msg("Could not find the host information for %s" %(db_hostname))
        return "UNKNOWN"

    trim_host = host.strip()

    if trim_host == 'mdw':
        master_on_mdw = True 
    elif trim_host == 'smdw':
        master_on_mdw = False
    else:
        log.msg("Unknown hostname %s found in /etc/gpnode on %s" %(trim_host, db_hostname))
        return "UNKNOWN"

    # Run healthmon_client on DB master. This can be run only on master/segment nodes, so run it remotely.
    # We only care about healthmon on active master to be running.
    cmd = "export LD_LIBRARY_PATH=/opt/dca/lib:$LD_LIBRARY_PATH;/opt/dca/bin/healthmon_client --command status"
    (retcode) = run_remote_command(db_hostname, cmd, True)

    # Return codes from healthmon_client - 0 = active on both, 1 = inactive on mdw, 2 = inactive on smdw, 3 = inactive on both
    if retcode == None or retcode > 3:
        log.msg("Unexpected return code from healthmon_client")
        return "UNKNOWN"

    if retcode == 0:
        return "NO"
    if retcode == 3:
        return "YES"
    if master_on_mdw and retcode == 1:
        return "YES"
    if master_on_mdw == False and retcode == 2:
        return "YES"
        
    return "NO"

def is_gpdb_running(hostname):

    socket_file = "/tmp/.s.PGSQL.%d" % pgport

    cmdStr = '%s -o """StrictHostKeyChecking no""" %s "ls -1 %s | grep PGSQL"' % (ssh_full_path, hostname, socket_file)

    return run_command(cmdStr)

def queries(params, dbuser, dbpass):

    if not params.has_key('op'):
        raise_db_error('No operation specified in query')

    if params['op'] == "pastqueries":
        query = """select username, query_text, b.rrrsqname, tstart as starttime, date_part('days', tfinish-tstart) as days, date_part('hours', tfinish-tstart) as hours, date_part('minutes', tfinish-tstart) as minutes, date_part('seconds', tfinish-tstart) as seconds from queries_history a, gp_toolkit.gp_resq_role b where a.username = b.rrrolname and a.status='done'"""
        if params.has_key('lookbackhours'):
            lookbackseconds = int(params['lookbackhours']) * 3600
            query += """ and date_part('epoch', current_timestamp - tsubmit) < %d """ % (lookbackseconds)
        else:
            query += """ and date_part('epoch', current_timestamp - tsubmit) < 3600"""
        query += """ union select username, query_text, b.rrrsqname, tstart as starttime, date_part('days', tfinish-tstart) as days, date_part('hours', tfinish-tstart) as hours, date_part('minutes', tfinish-tstart) as minutes, date_part('seconds', tfinish-tstart) as seconds  from queries_tail a, gp_toolkit.gp_resq_role b where a.username = b.rrrolname and a.status='done'"""


    if params['op'] == "currentqueries":
        query = """select username, query_text, b.rrrsqname, tstart as starttime, date_part('days', current_timestamp-tsubmit) as days, date_part('hours', current_timestamp-tsubmit) as hours, date_part('minutes', current_timestamp-tsubmit) as minutes, date_part('seconds', current_timestamp-tsubmit) as seconds from queries_now a, gp_toolkit.gp_resq_role b where a.username = b.rrrolname"""
        if params.has_key('status'):
            query += " and status='%s'" % (params['status'])

    log.msg('qry %s' % query)
    rows = []
    try:
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def resqueue(dbuser, dbpass):

    rows = []
    try:
        query = 'select * from pg_resqueue_attributes'
        rows = execute_query(query, dbuser, dbpass)
    except GPDBError, err:
        log.msg("Error calling execute_query from resqueue: %s" % err)
        raise GPDBError, 'Database error while fetching resource queue info'           
    except Exception, err:
        log.msg("Error calling execute_query from resqueue: %s" % err)
        raise Exception, 'Exception encountered while fetching resource queue info'
    except:
        log.msg("Unexpected error calling execute_query from resqueue: %s" % sys.exc_info()[0])
        raise

    return rows

def resqueue_mod(params):

    if not params.has_key('op'):
        raise_db_error('Operation not found in query')

    if not params.has_key('queuename'):
        raise_db_error('Queue name not found in query')

    escaped_queuename = params['queuename'].replace('"', '""')

    addparams = True
    if params['op'] == 'create':
        query = """CREATE RESOURCE QUEUE "%s" WITH (""" % (escaped_queuename)
    elif params['op'] == 'alter':
        query = """ALTER RESOURCE QUEUE "%s" WITH (""" % (escaped_queuename)
    elif params['op'] == 'delete':
        query = """DROP RESOURCE QUEUE "%s" """ %(escaped_queuename)
        addparams = False

    del(params['queuename'])

    del(params['op'])

    if addparams:
        i = 0
        for key in params.keys():
            if i > 0:
                query += ", "
            query += "%s = %s" % (key, params[key])
            i = 1
        query += ")"

    try:
        execute_query(query, pguser, None, True)
    except GPDBError, err:
        log.msg("Error calling execute_query from resqueue_mod: %s" % err)
        raise GPDBError, '%s' % err
    except Exception, err:
        log.msg("Error calling execute_query in resqueue_mod with sql %s: %s " % (query, err))
        raise Exception, 'Unexpected error in resqueue_mod: %s' % err
    except:
        log.msg("Unexpected error calling execute_query in resqueue_mod with sql %s: %s " % (query, sys.exc_info()[0]))
        raise

    return

def get_log_alert_level(dbuser, dbpass):
    sql = "select setting from pg_settings where name = 'gpperfmon_log_alert_level';" 

    # fetch gpperfmon_log_alert_level 
    log_alert_level = 'none'

    try:
        result = execute_query(sql, dbuser, dbpass)
    except GPDBError, err:
        log.msg("DB error calling execute_query from get_log_alert_level: %s" % err)
        raise GPDBError, 'Database error while fetching gpperfmon_log_alert_level'  
    except Exception, err:
        log.msg("Error calling execute_query from get_log_alert_level: %s" % err)
        raise Exception, 'Exception while fetching gpperfmon_log_alert_level' 
    except:
        log.msg("Unexpected error calling execute_query from get_log_alert_level: %s" % sys.exc_info()[0])
        raise

    # convert results to list of tuples
    if len(result) > 0:
        log_alert_level = result[0]['setting']

    return log_alert_level.upper()


def get_log_alert_sql(log_alert_level, severity, limit):
    '''
    Return log alert SQL based on alert level and underlying implementation method.
    '''
    sql_template =  '''SELECT to_char(logtime, 'MON-DD HH24:MI:SS.US') time, logpid, 
                              logseverity ||': '|| logmessage ||' (user: '|| loguser ||', db: '|| logdatabase ||', host: '|| loghost ||')' Description
                         FROM public.%s
                        WHERE logseverity IN %s
                        ORDER BY logtime DESC
                        LIMIT %s''' 
    if log_alert_level == 'NONE':
        alert_sql = sql_template % ('gp_log_master_ext', severity, limit)
    else:
        alert_sql = '(%s) UNION (%s) ORDER BY time DESC LIMIT %s' % (sql_template, sql_template, limit) 
        alert_sql = alert_sql % ('log_alert_now', severity, limit, 'log_alert_history', severity, limit)  

    return alert_sql


def alerts_summary(limit, severity, dbuser, dbpass):
    '''
    Purpose: Return a list of tuples containing the most recent N master log alerts.
        We combine multiple columsn from public.gp_log_master_ext into the  description
        column for ease of display in the UI.
    
    Returns:
        res:  List of tuples (date, description of alert)
    Raises:
        GPDBError
    '''
    global gp_log_alert_level
    if not gp_log_alert_level:
        gp_log_alert_level = get_log_alert_level(dbuser, dbpass)

    # min severity level to return
    if severity == 'LOG':
        log.msg("Severity 'LOG' is not supported")
        raise Exception, "Severity 'LOG' is not supported"
    elif severity == 'WARNING':
        severity = "('WARNING', 'ERROR','FATAL','PANIC')"
    elif severity == 'ERROR':
        severity = "('ERROR','FATAL','PANIC')"
    elif severity == 'FATAL':
        severity = "('FATAL','PANIC')"
    elif severity == 'PANIC':
        severity = "('PANIC')"

    alert_sql = get_log_alert_sql(gp_log_alert_level, severity, limit) 

    # fetch database alerts
    try:
        alerts = execute_query(alert_sql, dbuser, dbpass)
    except GPDBError, err:
        log.msg("DB error calling execute_query from alerts_summary: %s" % err)
        raise GPDBError, 'Database error while fetching database alerts'  
    except Exception, err:
        log.msg("Error calling execute_query from alerts_summary: %s" % err)
        raise Exception, 'Exception while fetching database alerts' 
    except:
        log.msg("Unexpected error calling execute_query from alerts_summary: %s" % sys.exc_info()[0])
        raise

    # convert results to list of tuples
    alert_summary = list()
    for row in alerts:
        alert_time = row['time']
        alert_desc = row['description']

        alert_summary.append( (alert_time, alert_desc ) )

    return alert_summary

def dialhome_summary(limit, severity, dbuser, dbpass):
    '''
    Purpose: Return a list of tuples containing the most recent N dial home
        events.  The events are sorted by severity, then date.  We combine
        multiple columsn into description for ease of display in the UI.
    
    Returns:
        res:  List of tuples (date, hostname, description of dial home event)
    Raises:
        GPDBError
    '''

    # min severity level to return
    if severity == 'INFO':
        severity = "('Error','Info','Unknown','Warning')"
    elif severity == 'WARNING':
        severity = "('Error','Unknown','Warning')"
    elif severity == 'ERROR':
        severity = "('Error','Unknown')"

    dh_sql = '''select to_char(a.ctime, 'MON-DD HH24:MI:SS') time,
                       a.hostname,
                       a.severity ||': '|| a.message ||' (Symptom code '|| a.symptom_code ||'.'|| a.detailed_symptom_code ||')' Description
                  from emcconnect_history a
                 where severity in %s 
                 order by ctime desc
                 limit %s''' % (severity, limit)

    # fetch dialhome events
    try:
        dh_events = execute_query(dh_sql, dbuser, dbpass)
    except GPDBError, err:
        log.msg("DB error calling execute_query from dialhome_summary: %s" % err)
        raise GPDBError, 'Database error while fetching dialhome events'
    except Exception, err:
        log.msg("Error calling execute_query from dialhome_summary: %s" % err)
        raise Exception, 'Exception while fetching dialhome events'
    except:
        log.msg("Unexpected error calling execute_query from dialhome_summary: %s" % sys.exc_info()[0])
        raise

    # convert results to list of tuples
    dh_summary = list()
    for row in dh_events:
        dh_time = row['time']
        dh_host = row['hostname']
        dh_desc = row['description']

        dh_summary.append( (dh_time, dh_host, dh_desc ) )

    return dh_summary

def getmodule_info(dbuser, dbpass, cap_file):
    '''
        Purpose:
            Fetch the module count from the dca_setup configuration file and also returns the suggested module description.
            The GPDB module description is based on GPDB being high capacity or not.
    '''

    gpdb_hosts_count = etl_hosts_count = hdm_hosts_count = hdw_hosts_count = hdc_hosts_count = hbw_hosts_count = 0
    try:
        GPDB_desc = ''; ETL_desc = 'DIA'; HDM_desc = 'GPHD Master'; HDW_desc = 'GPHD Worker'; HDC_desc = 'GPHD Compute'; HBW_desc = "Hbase"
        #The productid file contains an identifier which indicates if the GPDB is standard or high capacity.
        try:
            fd = open(cap_file, 'r')
        except Exception, e:
            log.msg("Exception when opening file %s: %s" % (cap_file, e.__str__().strip()))
            raise Exception, 'Exception when opening file: %s, %s' %(cap_file, e.__str__().strip())
        except:
            log.msg("Exception when opening file %s: %s" % (cap_file, e.__str__().strip()))
            raise

        #Identifier 'DCA1-SYSRACK' indicates standard GPDB where as 'DCA1-CAPRACK' indicates high capacity.
        try:
            GPDB_product_desc = fd.readline().strip()
        except Exception, e:
            log.msg("Exception when reading file %s: %s" % (cap_file, e.__str__().strip()))
            raise Exception, 'Exception when reading file: %s, %s' %(cap_file, e.__str__().strip())
        except:
            log.msg("Error when reading file %s %s" % (cap_file, sys.exc_info()[0]))
            raise

        if GPDB_product_desc == 'DCA1-SYSRACK':
            GPDB_desc = 'GPDB Std'
        elif GPDB_product_desc == 'DCA1-CAPRACK':
            GPDB_desc = 'GPDB HiCap'
        else:
            raise Exception("Incorrect productid in file %s" %(cap_file))

        fd.close()

        return (GPDB_desc, ETL_desc, HDM_desc, HDW_desc, HDC_desc, HBW_desc)
    except Exception, e:
        log.msg("Unexpected exception from moduledetails WS: %s" % e.__str__().strip())
        raise Exception, 'Unexpected exception from moduledetails WS: %s' % e.__str__().strip()
    except:
        log.msg("Unexpected error from moduledetails WS %s" % (sys.exc_info()[0]))
        raise


def getgpdbversion(dbuser, dbpass):
    query = "select version();"
    try:
        res = execute_query(query, dbuser, dbpass)
    except GPDBError, err:
        log.msg("Error calling execute_query from getgpdbversion: %s" % err)
        raise GPDBError, 'Database error while fetching GDDB version info %s' % err
    except Exception, err:
        log.msg("Error calling execute_query from getgpdbversion: %s" % err)
        raise Exception, 'Exception encountered while fetching GPDB version info %s' % err
    except:
        log.msg("Unexpected error calling execute_query from getgpdbversion: %s" % sys.exc_info()[0])

    return res

def getgpdbversiontuple(dbuser, dbpass):
    '''
    return a list contains gpdb version in format (major, minor, release, patch).
    major and minor are mandatory. release and patch are optional.
    minor/release/patch could be string like '4.3_MAIN', '4.2.6.1BR'.
    ''' 
    pattern = r'^PostgreSQL 8\.2\.\d+ \(Greenplum Database (\d.*?) '
    gpdbVersionString = getgpdbversion(dbuser, dbpass)
    matchObj = re.search(pattern, gpdbVersionString[0]['version'])
    if not matchObj:
        raise Exception, "gpdb version is not in expected format: %s" % (gpdbVersionString)

    versiontuple = [ e.strip() for e in matchObj.group(1).split('.') ] 
    if len(versiontuple) < 2 or len(versiontuple) > 4:
        raise Exception, "gpdb version is not in expected format: %s" % (gpdbVersionString)
    return versiontuple

def getgpdb_numericversion(dbuser, dbpass):
    '''
    return version list in numeric, other characters will be discarded.
    eg: 4.2br --> 4.2.0.0
    '''
    result = []
    version = getgpdbversiontuple(dbuser, dbpass)
    length = len(version)
    for i in xrange(length):
        e = version[i]    
        result.append(string2int(e))

    for i in xrange(4 - length):
        result.append(0)

    return result

def string2int(str):
    result = 0
    for i in str:
        if not i.isdigit():
            break
        result = result * 10 + int(i)
    return result    

def getapi(api_list, dbuser, dbpass):
    ''' 
        Purpose: return the API's supported by a particular GPDB verison.
        Details: 
                The blacklist of the API's for the various GPDB verion are as below:
                4.0   :  ['/cancelquery', 'diskusagehistory', 'diskusagesummary']
                4.1   :  ['/cancelquery', 'diskusagehistory', 'diskusagesummary']
                4.2.0 :  ['/cancelquery', 'diskusagehistory', 'diskusagesummary']
                4.2.1 :  supports all
    '''
               
    try:
        ad = {}    
        for api in api_list:
           ad[api] = 1;

        akeys = ad.keys()
        akeys.sort()

        (major, minor, thirdpart, unused)= getgpdb_numericversion(dbuser, dbpass)

        if major == 4 and minor == 0:
            akeys = filter(lambda i: i != 'cancelquery' and i != 'diskusagehistory' and i != 'diskusagesummary', ad.keys())
            akeys.sort()
            return akeys

        if major == 4 and minor == 1:
            akeys = filter(lambda i: i != 'cancelquery' and i != 'diskusagehistory' and i != 'diskusagesummary', ad.keys())
            akeys.sort()
            return akeys

        if major == 4 and minor == 2 and thirdpart == 0:
            akeys = filter(lambda i: i != 'cancelquery' and i != 'diskusagehistory' and i != 'diskusagesummary', ad.keys())
            akeys.sort()
            return akeys

        if major == 4 and minor == 2 and thirdpart > 0:
            akeys.sort()
            return akeys

        return akeys
    except Exception, err:
        log.msg("Error from getapi WS: %s" % err)
        raise Exception, 'Exception encountered while fetching api strings %s' % err
    except:
        log.msg("Unexpected error calling execute_query from getapi: %s" % sys.exc_info()[0])
        raise

def getguc(gucname, dbuser, dbpass):
    '''
    Purpose:
        Fetch the distinct list of values for a GUC across the cluster.  For segdb's we return
        every unique value (there can be multiple).  The master node always has a single
        value. We also return a boolean value for balanced to indicate if the cluster has
        the GUC set consistently across the cluster.

    Notes:
        This WS only returns the current (running) value for the GUC's.  It is not aware of
        values that are set in the postgresql.conf.

    Returns
        master_value: List with single tuple of (guc value, guc scale)
        segment_values: List of tuples (guc value, guc scale)
        balanced: boolean to indicate if GUCs are set consistently across segment nodes
        guc_min: min possible value for guc
        guc_max: max possible value for guc
        guc_scale: The scale associated with the segment_values, guc_min, guc_max.  Scale
                    can be kB, MB, GB as well as min, s, etc...
    Raises
        GPDBError
        NoDataError -- GUC doesn't exist
    '''

    guc_info = "SELECT name, setting, unit, short_desc, context, vartype, min_val, max_val FROM pg_settings where name = '%s'" % gucname
    segment_guc = "select paramname, paramvalue from gp_toolkit.gp_param_setting('%s') where paramsegment > -1 group by paramname, paramvalue" % gucname
    master_guc  = "select paramname, paramvalue from gp_toolkit.gp_param_setting('%s') where paramsegment = -1" % gucname

    # Make sure GUC exists
    try:
        gucinfo = execute_query(guc_info, dbuser, dbpass)
    except GPDBError, err:
        log.msg("Error calling execute_query from getguc: %s" % err)
        raise GPDBError, 'Database error while fetching GUC info'
    except Exception, err:
        log.msg("Error calling execute_query from getguc: %s" % err)
        raise Exception, 'Exception encountered while fetching GUC info'
    except:
        log.msg("Unexpected error calling execute_query from getguc: %s" % sys.exc_info()[0])
        raise

    # Raise if GUC doesn't exist
    if not gucinfo.__len__():
        raise NoDataError, 'Invalid GUC: %s' % gucname

    for row in gucinfo:
        setting = row['setting']
        guc_scale = row['unit']
        guc_min = row['min_val']
        guc_max = row['max_val']
        guc_type = row['vartype']

    # Fetch GUC value for master and segments
    try:
        segment_res = execute_query(segment_guc, dbuser, dbpass)
        master_res = execute_query(master_guc, dbuser, dbpass)
    except GPDBError, err:
        log.msg("Error calling execute_query from getguc: %s" % err)
        raise GPDBError, 'Database error while fetching GUC values'
    except Exception, err:
        log.msg("Error calling execute_query from getguc: %s" % err)
        raise Exception, 'Exception encountered while fetching GUC values'
    except:
        log.msg("Unexpected error calling execute_query from getguc: %s" % sys.exc_info()[0])
        raise

    # convert segment_res to list of tuples
    segment_values = list()
    for row in segment_res:
        pval = row['paramvalue']
        plen = pval.__len__()

        # remove kB|MB|GB scale from int's
        if (guc_type == 'integer') & ( pval[-1:] == 'B' ):
            pscale = pval[plen - 2:]  
            pval = pval[0:plen - 2]
        else:
            pscale = guc_type

        segment_values.append( (pval, pscale) )

    # check if GUC is same on all segments (balanced)
    if segment_values.__len__() > 1:
        balanced = False
    else:
        balanced = True

    # convert master_res to tuple of (guc value, guc scale)
    master_value = list()
    for row in master_res:
        pval = row['paramvalue']
        plen = pval.__len__()

        # remove kB|MB|GB scale from int's
        if (guc_type == 'integer') & ( pval[-1:] == 'B' ):
            pscale = pval[plen - 2:]
            pval = pval[0:plen - 2]
        else:
            pscale = guc_type

        master_value.append( (pval, pscale) )

    return master_value, segment_values, balanced, guc_min, guc_max, guc_scale

def roles(dbuser, dbpass):

    rows = []
    try:
        query = 'select * from gp_toolkit.gp_resq_role'
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def roles_mod(params, dbuser, dbpass):

    if not params.has_key('op'):
        raise_db_error('No operation specified in query')

    if params['op'] == "add2queue":
        query = """ALTER ROLE %s RESOURCE QUEUE %s""" %(params['role'], params['queuename']) 
    elif params['op'] == "deletefromqueue":
        query = """ALTER ROLE %s RESOURCE QUEUE none"""  %(params['role'])

    log.msg('qry %s' % query)
    try:
        execute_query(query, dbuser, dbpass, True)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return

def db_list(dbuser, dbpass):

    query = """select datname from pg_database where datistemplate='f' and datallowconn='t'"""
    try:
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def db_installing_user(dbuser, dbpass):

    query = """select usename from pg_user where usesysid=10;"""
    try:
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return (rows[0])['usename']

# return None for success
# return string for error
def compare_user_with_current_unix_uer(username):

    try:
        currentUser = pwd.getpwuid(os.getuid())[0]
    except Exception, e:
        log.msg(e.__str__())
        return "Could not validate username due to exception"
    except:
        return "Could not validate username due to exception"

    if currentUser == username:
        return None
    else:
        return ("Specified user (%s) does not match expected (%s)" % (username, currentUser))

# return True for success, False for failure
def test_unix_authorization(hostname, username, password):

    authorized = False
    echostr = "gpperfmon_%s" % hostname
    child = None
    
    try:
        cmdStr = "%s -l %s -o 'PubkeyAuthentication no' %s 'echo %s'" % (ssh_full_path, username, hostname, echostr)
        child = pexpect.spawn(cmdStr)
        sent_already = False
    
        while 1:
            index = child.expect(["password", "Password", echostr, pexpect.EOF, pexpect.TIMEOUT], timeout=15)
            if index == 0 or index == 1:
                if sent_already:
                    break
                else:
                    child.sendline(password)
                    sent_already = True
            elif index == 2:
                authorized = True
            elif index == 3:
                break
            elif index == 3:
                break
    except Exception, e:
        log.msg("exception in test_unix_authorization")
        log.msg(e.__str__())
    except:
        log.msg("unknown exception in test_unix_authorization")
    
    try:
        # close if possible, silence errors
        child.close()
    except:
        pass
    
    return authorized

def get_fsmap(master_server):
    gphomepath = os.environ.get('GPHOME')
    cmdStr = 'source %s/greenplum_path.sh; gpgenfsmap.py' % (gphomepath)
    
    return run_remote_command(master_server, cmdStr)
    
def gpstart(master_server, token):

    directory = os.path.join(os.getcwd(), '..', 'commands')

    cmdStr = 'gpwsrunner.py --commandline "gpstart -a" --directory %s --application gpstart --token %s --group gpcontrol --remotehost %s' % (directory, token, master_server)

    return run_command(cmdStr)

def gpconfig(master_server, token, guc, value, masterval):

    directory = os.path.join(os.getcwd(), '..', 'commands')

    cmdStr = 'gpwsrunner.py --commandline "gpconfig -c %s -v %s -m %s" --directory %s --application gpconfig --token %s --group gpcontrol --remotehost %s' % (guc, value, masterval, directory, token, master_server)

    return run_command(cmdStr)


def gpstop(master_server, token, mode, restart):

    directory = os.path.join(os.getcwd(), '..', 'commands')

    if restart == 'TRUE':
        cmdStr = 'gpwsrunner.py --commandline "gpstop -ar -M %s" --directory %s --application gpstop --token %s --group gpcontrol --remotehost %s' % (mode,  directory, token, master_server)
    else:
        cmdStr = 'gpwsrunner.py --commandline "gpstop -a -M %s" --directory %s --application gpstop --token %s --group gpcontrol --remotehost %s' % (mode,  directory, token, master_server)

    return run_command(cmdStr)

# return True for success, False for failure
def check_for_gpdf(master_server):

    filename = "%s/bin/gp_df" % gpperfmonhome

    cmdStr = '%s %s "ls -1 %s | grep gp_df"' % (ssh_full_path, master_server, filename)

    log.msg(cmdStr)

    return run_command(cmdStr)

def check_for_gpgenfsmap(master_server):
    
    filename = "%s/bin/gpgenfsmap.py" % gphome

    cmdStr = '%s %s "ls -1 %s | grep gpgenfsmap.py"' % (ssh_full_path, master_server, filename)

    log.msg(cmdStr)

    return run_command(cmdStr)

def genServerFsList(username, password):
    serverFSMap = dict()
    query = "select distinct(hostname) from gp_segment_configuration"

    try:
        results = execute_query(query, username, password)
        if len(results) == 0:
            logger.error( "Error: gp_segment_configuration empty" )
            sys.exit(1)
        for item in results:
            serverFSMap[item['hostname']] = 1
        hostlist = serverFSMap.keys()
    except GPDBError, err:
        log.msg("Error while fetching the server list: %s" % err)
        raise GPDBError, 'Database error while fetching hostname info'
    except Exception, err:
        log.msg("Error while fetching the server list: %s" % err)
        raise Exception, 'Exception encountered while fetching hostname info'
    except:
        log.msg("Unexpected error while fetching the server list: %s" % sys.exc_info()[0])
        raise

    return hostlist

def gprecoverseg(master_server, full, token, rebalance):

    if full == 'yes':
        cmdln = "gprecoverseg -a -F"
    elif rebalance == 'yes':
        cmdln = "gprecoverseg -a -r"
    else:
        cmdln = "gprecoverseg -a"

    directory = os.path.join(os.getcwd(), '..', 'commands')

    cmdStr = 'gpwsrunner.py --commandline "%s" --directory %s --application gprecoverseg --token %s --group gpcontrol --remotehost %s' % (cmdln, directory, token, master_server)

    return run_command(cmdStr)

def pre_recoverseg_check(master_server, token):

    directory = os.path.join(os.getcwd(), '..', 'commands')

    cmdline = "%s/bin/gp_prerecoverseg_check --host 127.0.0.1 --user gpmon --port %d" % (gpperfmonhome, pgport)

    cmdStr = """gpwsrunner.py --commandline "%s" --directory %s --application pre_recoverseg_check --token %s  --remotehost %s """ % (cmdline, directory, token, master_server)

    return run_command(cmdStr)


def spaceusage(master_server, dbnamelist,  db_installation_user, token):

    directory = os.path.join(os.getcwd(), '..', 'commands')

    #query = """select current_timestamp, relstorage, sum\\(sotailtablesizedisk\\)/\\(1024*1024\\) as tablesizedisk, sum\\(sotailtablesizeuncompressed\\)/\\(1024*1024\\) as tablesizeuncompressed, sum\\(sotailindexessize\\)/\\(1024*1024\\) as indexessize from gp_toolkit.gp_size_of_table_and_indexes_licensing, pg_class where sotailoid = pg_class.oid group by relstorage"""

    cmdStr = """gpwsrunner.py --commandline "runquery.py --spaceusage --dblist %s --user %s" --directory %s --application spaceusage --token %s  --remotehost %s --nostreaming """ % (dbnamelist, db_installation_user, directory, token, master_server)
    log.msg(cmdStr)

    return run_command(cmdStr)

def get_pre_recoverseg_output():

    try:
        filename = os.path.join(os.getcwd(), '..', 'commands', 'pre_recoverseg_check.output')
        fd = open(filename)
        output = fd.read()
        fd.close()
        return output
    except Exception, e:
        log.msg(e.__str__())
        return None
    except:
        return None

def check_pre_recoverseg_output(output):

    if not re.search("type=OUTPUT_START", output):
        return False

    if not re.search("type=OUTPUT_END", output):
        return False

    return True


def parse_pre_recoverseg(output):

    segments = list() # list of kvp dictionaries, 1 per segmnet
    devices = list() # list of kvp dictionaries, 1 per device

    currentDict = None
    currentIsSegment = True

    for line in output.splitlines():
        
        fields = line.split(";")

        for kvp in fields:

            tokens = kvp.split("=")
            if len(tokens) != 2:
                continue

            key = tokens[0]
            value = tokens[1]

            if key == 'type':
                if currentDict:
                    if currentIsSegment:
                        segments.append(currentDict)
                    else:
                        devices.append(currentDict)

                if value == 'SEGMENT_INFO':
                    currentIsSegment = True
                    currentDict = dict()
                elif value == 'HOST_DEVICE_INFO':
                    currentIsSegment = False
                    currentDict = dict()
                else:
                    currentDict = None

            elif currentDict is None:
                    continue
            else:
                currentDict[key] = value


    return (segments, devices)


def get_application_meta_data(application, get_output, firstbyte):

    args = ''
    starttime = ''
    token = ''
    status = ''
    retCode = ''
    byte_num = 0
    output = ''
    read_size = 1024

    if get_output == 'yes':
        get_output = True
    else:
        get_output = False

    try:
        firstbyte  = int(firstbyte)
    except:
        firstbyte = 1

    metaname = "%s.metadata" % application
    outname = "%s.output" % application
    metafile = os.path.join(os.getcwd(), '..', 'commands', metaname)
    outfile = os.path.join(os.getcwd(), '..', 'commands', outname)

    try:
        fd = open(metafile)
        for line in fd:
            fields = line.strip().split()
            if len(fields) <= 1:
                continue

            if fields[0] == 'CommandLine':
                args = " ".join(fields[1:]).strip()
            elif fields[0] == 'StartTime':
                starttime = " ".join(fields[1:]).strip()
            elif fields[0] == 'Token':
                token = " ".join(fields[1:]).strip()
            elif fields[0] == 'Status':
                status = " ".join(fields[1:]).strip()
            elif fields[0] == 'ReturnCode':
                retCode = " ".join(fields[1:]).strip()
        fd.close()
    except Exception, e:
        log.msg(e.__str__())
        log.msg("exception reading file %s" % metafile)
    except:
        log.msg("unknown exception reading file %s" % metafile)

    if get_output:
        try:
            fd = open(outfile, 'rb')
            fd.seek(firstbyte)
            output = fd.read(read_size)

            read = len(output)
            if read < read_size:
                byte_num = firstbyte + read - 2
                output = output[0:-1] # remove a trailing newline that seems to be present
            else:
                byte_num = firstbyte + read_size - 1
            fd.close()

        except Exception, e:
            log.msg(e.__str__())
            log.msg("exception reading file %s" % outfile)
        except:
            log.msg("unknown exception reading file %s" % outfile)
    
    return (args, starttime, token, status, retCode, byte_num, output)

#Gets a list of all the segment dbs, and the directory names where they are stored
def segmentdbdirconfiguration(dbuser, dbpass):
    
    rows = []
    try:
        query = "select dbid, content, role, preferred_role, hostname, fselocation from gp_segment_configuration , pg_filespace_entry where gp_segment_configuration.dbid = pg_filespace_entry.fsedbid"
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def segmentconfiguration(dbuser, dbpass, instance_name):

    rows = []
    try:

        query = 'select (h).* from (select (a).* from (select %s.segment_configuration_recovery(segconf.dbid, segconf.content, segconf.role, segconf.preferred_role, segconf.mode, segconf.status, segconf.port, segconf.hostname, segconf.address, segconf.replication_port, count, latest_event, latest_event_description) as a from gp_segment_configuration segconf left outer join (select T.*, gch.desc as latest_event_description from (select dbid, count(*) as count, max(time) as latest_event from gp_configuration_history group by dbid) as T, gp_configuration_history as gch where T.dbid=gch.dbid and T.latest_event=gch.time) as conf_hist on segconf.dbid=conf_hist.dbid where segconf.content>=0) as g) as h' % instance_name

        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def diskspacesegmentconfiguration(dbuser, dbpass):

    rows = []
    try:
        query = "select * from gp_segment_configuration where content>=0"
        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)
    return rows

def segmentconfigurationhistory(dbuser, dbpass, dbid, limit):

    rows = []
    try:
        if dbid:
            query = "select * from gp_segment_configuration where dbid = %d" % dbid
            rows = execute_query(query, dbuser, dbpass)
            if not rows:
                return 0
        query = """select to_char(time, 'YYYY-MM-DD HH24:MI:SS') as time, dbid, "desc" from gp_configuration_history"""
        query += ' where dbid = %d order by time desc limit %d' % (dbid, limit)

        rows = execute_query(query, dbuser, dbpass)
    except:
        log.msg('error during query: %s' % query)
        raise_db_error('Exception during query: %s' % query)

    return rows

def getadminuser(master_server):
    currentUser = None
    try:
        currentUser = pwd.getpwuid(os.getuid())[0]
    except Exception, e:
        log.msg(e.__str__())
        return None
    except:
        return None
        
    return currentUser
