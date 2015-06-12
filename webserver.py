#!/usr/bin/env python

import os, sys, socket, re, ConfigParser, types, operator, subprocess, string
from xml.sax.saxutils import escape
import time, datetime, tempfile
import resource, thread
import urllib2
from socket import gethostname
from gppylib.commands.base import WorkerPool, Command, REMOTE
from Cookie import SimpleCookie
import json
datadir = os.getenv('MASTER_DATA_DIRECTORY', None)

sys.path.append(os.path.join(sys.path[0], 'lib'))

import web
from greenplum import db
from greenplum import error
from greenplum import interval
from greenplum import gplog
from model import pg

isAppliance = False
isV1Appliance = False
isAppliance = os.path.exists('/etc/gpdb-appliance-version')
if isAppliance:
    try:
        fd = open('/etc/gpdb-appliance-version')
        data = fd.read()
        if data and len(data) > 0:
            first_char = data[0]
        if first_char == '1':
            isV1Appliance = True
    except:
        pass
    finally:
        if fd:
            fd.close()

FILEPATH_TO_DCASETUP_SETTINGS = "/opt/dca/etc/dca_setup/dca_settings_live.cnf"

# FOR V1 DCAs only
if isV1Appliance:
    sys.path.append('/opt/dca/lib')
    try:
            from dca_setup.dca_config_generator import UserInputConfiguration, DcaSetupConfigFileParser, FILEPATH_TO_DCASETUP_SETTINGS
    except ImportError, err:
        sys.exit('Error importing DCA libraries: %s' % err)

MAX_AGGREGATED_SAMPLES = 2000
MAX_NONAGGREGATED_SAMPLES = 16
MAX_STORAGE_SAMPLES = 200
MAX_QUERIES_PER_SEARCH = 250
ONE_DAY_IN_SECONDS = 86400
remote = False
verbose = False
displayed_server_name = ''
ssl_enabled = False 
gpperfmon_version = '1.3.0.0 build 91'
csrf_enabled = True
gss_status = False
debug_mode = False
secureDbHealth = False
maxOpenConnections = 5
dbHealth_PollInterval = 30000
sessionTimeout = 1800
clientSSl_Status = False
auth_mech = 'null'
diskThresholdValue = 80
allowAutoLogin = True

db_access_last_time = 0
dbstatus = 'NORMAL' 
gpdb_server_name = '127.0.0.1'
DB_STATE_CHECK_INTERVAL = 30
hdInstalled = False

filespace_list_cache = None
productid = None
GPDB_PRODUCT_ID_FILE = '/opt/greenplum/conf/productid'
MODULE_SIZE = 4
MODULE_SIZE_V2 = 2

instance_name = 'test' 
tmp_schema_name = 'gpcmdr_instance_%s' % instance_name

app = render = session = None

urls = ('/', 'index',
        '/goods_list', 'goods_list',
        '/goods_info', 'goods_info',
        '/logon', 'logon',
        '/logoff', 'logoff',
        '/hosts', 'hosts',
        '/database', 'database',
        '/system', 'system',
        '/queries', 'queries',
        '/querydetails', 'querydetails',
        '/queryplan', 'queryplan',
        '/queryexplain', 'queryexplain',
        '/getquerypriority', 'getquerypriority',
        '/setquerypriority', 'setquerypriority',
        '/cancelquery', 'cancelquery',
        '/health', 'health',
        '/healthdetails', 'healthdetails',
        '/gpdbup', 'gpdbup',  
        '/gpstart', 'gpstart',  
        '/gpstop', 'gpstop',  
        '/gprecoverseg', 'gprecoverseg',  
        '/gp_prerecoverseg_check', 'gp_prerecoverseg_check',
        '/segmentconfig', 'segmentconfig',  
        '/segment_config_history', 'segment_config_history',  
        '/resqueue', 'resqueue',
        '/roles', 'roles',
        '/gpconfig', 'gpconfig',
        '/diskusagesummary', 'diskusagesummary',
        '/diskusagehistory', 'diskusagehistory',
        '/uptime', 'uptime',
        '/getadminusername', 'getadminusername',
        '/guc', 'guc',
        '/dialhome_summary', 'dialhome_summary',
        '/alerts_summary', 'alerts_summary',
        '/moduledetails', 'moduledetails',
        '/healthinfo', 'healthinfo',
        '/multiCluster', 'multiCluster',
        '/getStatus', 'getStatus',
        '/gpwlm_throttle', 'gpwlm_throttle',
        '/gpwlm_unthrottle', 'gpwlm_unthrottle',
        '/gpwlm_get_throttled_queries', 'gpwlm_get_throttled_queries',
        '/rule_add', 'rule_add',
        '/rule_delete', 'rule_delete',
        '/rule_modify', 'rule_modify',
        '/autologininfo', 'autologininfo',
)

app = web.application(urls, locals())
session = web.session.Session(app, 
                              web.session.DiskStore(tempfile.mkdtemp(dir=os.path.join(os.getcwd(), 'runtime', 'sessions'))), 
                              initializer={'user': '', 'password' : '', 'role': {}, 
                                           'loggedin': 0, 'gpperfmon_instance_name': instance_name, 'csrf_token':''})

# either a operator or superuser
def isOperatorOrSuper():
    if not session or not session.role:
        return False
    if session.role['superuser']:
        return True
    if session.role['operator']:
        return True
    return False

def isSuperUser():
    if not session or not session.role:
        return False
    if session.role['superuser']:
        return True
    return False

def cleanKrbFile():
    krb = False
    if web.ctx.env.has_key('KRB5CCNAME') :
        krb = True
        if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
            db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
    return krb

render = web.template.render('./templates/', cache=False)

# Flex doesn't expose the body of non-200 errors so returning 200 with
# structured error in contents
def page_not_found():
    web.ctx.headers = [('Content-Type', 'text/xml')]
    web.ctx.status = '200 OK';
    return mkerr(error.BADREQ, 'Invalid command')

def internal_error():
    web.ctx.headers = [('Content-Type', 'text/xml')]
    web.ctx.status = '200 OK';
    (type, value) = sys.exc_info()[:2]
    return mkerr(error.INTERNAL, '%s: %s' % (type, value))

def generate_csrf_token():
    """generate random csrf token"""
    from uuid import uuid4
    return uuid4().hex

def csrf_protected(f):
    def get_csrf_token():
        csrf_token = None

        # AJAX: get csrf token from header: X-CSRF-TOKEN
        csrf_token = web.ctx.env.get('HTTP_X_CSRF_TOKEN')

        # FORM: get csrf token from hidden input 'csrf'
        if not csrf_token:
            inp = web.input()
            if (inp and inp.has_key('csrf')):
                    csrf_token = inp.csrf
        return csrf_token

    def decorated(*args,**kwargs):
        if not csrf_enabled:
            return f(*args,**kwargs)

        csrf_token = get_csrf_token()
        try:
            session.csrf_token
        except :
            if csrf_token :
                session.csrf_token = csrf_token
            else :
                web.ctx.headers = [('Content-Type', 'text/xml')]
                web.ctx.status = '200 OK';
                return mkerr(error.BADREQ, 'no csrf token or token is invalid')

        if csrf_token and (csrf_token == session.csrf_token):
            return f(*args,**kwargs)

        web.ctx.headers = [('Content-Type', 'text/xml')]
        web.ctx.status = '200 OK';
        return mkerr(error.BADREQ, 'no csrf token or token is invalid')

    return decorated

class getStatus():
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        if i.has_key('url'):
            try:
                response = urllib2.urlopen(i['url'])
                getinfo = response.read()
                return getinfo
            except urllib2.URLError, e:
                log.msg("URL error: %s error: %s" %(i['url'], str(e.reason)))
                return mkerr('UNREACHABLE', str(e.reason))
            except urllib2.HTTPError, e:
                log.msg("HTTP error: %s" %(str(e.code)))
                return mkerr('UNREACHABLE', str(e.code))
            except urllib2.HTTPException, e:
                log.msg("HTTP exception: %s" %(e))
                return mkerr('UNREACHABLE', str(e))


class multiCluster():
    def GET(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')
        global auth_mech

        if web.ctx.env.has_key('KRB5CCNAME') :
            if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
                db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])

        i = web.input()
        if i.has_key('auto'):
            if not session.loggedin:
                return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
            else :
                return render.viewMultiCluster()
        elif (web.ctx.env.has_key('SSL_CLIENT_S_DN_CN')):
            auth_mech = "pki"
            (dbName, status) = db.getGPDBUsername( web.ctx.env['SSL_CLIENT_S_DN_CN'])
            if status :
               username = dbName
               password = 'BOGUS_FOR_PKI'
            else :
               return mkerr(error.ACCESS_DENIED, 'Client cerificate username not mapped with GPDB username ')
            message = ''
            try:
                message = authrole(username, password, auth_mech)
            except db.GPDBError, errorinfo:
                return mkerr(error.DATA_ACCESS, errorinfo.__str__())

            if not session.loggedin:
                return mkerr(error.ACCESS_DENIED, message)

            csrf_token = generate_csrf_token()
            session.csrf_token = csrf_token

            return render.viewMultiCluster()
        else :
            return render.multiCluster(gpperfmon_version, displayed_server_name)


class healthinfo():
    def GET(self):
        global secureDbHealth, auth_mech        

        web.header('Content-Type', 'application/json')
        web.header('Cache-Control', 'no-store')
        web.header('Access-Control-Allow-Origin', '*')

        i = web.input(start='NOW', end='NOW', interval='1min')
        callbackFunction = i['callback']

        has_kerb = False
        if web.ctx.env.has_key('KRB5CCNAME') :
            if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
                db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
            has_kerb = True
        if not secureDbHealth :
            username = 'gpmon'
            password = os.environ.get('PGPASSWORD', '')
        else :
            if session.loggedin :
                username = session.user
                password = session.password
            else :
                data = [{'Error':True, 'Message':"You must be logged on to perform this operation"}]
                responseData = callbackFunction + '(' + json.dumps(data) + ')'
                return responseData
        try:
            database_up = db.is_gpdb_running(gpdb_server_name)
            dbstatus = db.database_state(username, password, auth_mech)
            if not dbstatus == 'DOWN':
                res = db.database_now(True, 'gpmon',os.environ.get('PGPASSWORD', ''))
            (gpdbUptime, gpdbVersion, openConnections, serverTime, dcaVersion, dcaSerialNumber) = db.get_uptime(username, password, isAppliance, tmp_schema_name)
        except Exception, e:
            data = [{'Server':i['serverName'], 'Error':True, 'Message':e.__str__()}]
            responseData = callbackFunction + '(' + json.dumps(data) + ')'
            return responseData

        if not gpdbUptime:
            data = [{'Server':i['serverName'], 'Error':True, 'Status':database_up, 'DbStatus':dbstatus, 'Message':"data not returned from Uptime query"}]
            responseData = callbackFunction + '(' + json.dumps(data) + ')'
            return responseData


        parts = gpdbVersion.split("Greenplum Database ")
        if len(parts) > 1:
            gpdbVersion = parts[1]
        parts = gpdbVersion.split(")")
        gpdbVersion = parts[0]

        if dbstatus == 'DOWN':
            res = None

        if res:
            (tkeys, ckeys, tab) = res
        else:
            tkeys = None
            ckeys = None
            tab = None
        queriesRunning = 0
        if tkeys :
            for t in tkeys :
                v = tab[t]
                queriesRunning = v["queries_running"]
        gpdbDescription = 'Greenplum Status'

        data = [{'ActiveQueries':str(queriesRunning), 'DbStatus':dbstatus, 'Server':i['serverName'], 'Status':database_up, 'GpdbDescription':gpdbDescription, 'GpdbStartTime':gpdbUptime, 'GpdbVersion':gpdbVersion, 'DcaVersion':dcaVersion, 'DcaSerialNumber':dcaSerialNumber, 'NumOpenConnections':openConnections, 'LocalServerTime':serverTime}]
            
        responseData = callbackFunction + '(' + json.dumps(data) + ')' 
        return responseData

# run_command modified from gpcmdr.py
def run_command(cmd):
    retcode = None
    msg = None
    emsg = None
    try:
        p = subprocess.Popen(cmd, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        result = p.communicate()
        retcode = p.returncode
        msg = result[0].strip()
        emsg = result[1].strip()
    except Exception, e:
        log.msg('ERROR: run_command failed. Detail: ' + str(e))
    return (retcode, msg, emsg)

def run_gpwlm(args):
    home = os.environ.get('HOME')
    if not home:
        log.msg('HOME not set. Cannot run gpwlm.');
        return(1, None, None)
    bin = home + '/gp-wlm/bin/gp-wlm '
    cmd = bin + args
    return run_command(cmd)

def authrole(username, password, auth_mech):
    # check db status
    dbstatus_msg = ''
    dbstatus = db.database_state(username, password, auth_mech)
    # if db is not accessible, set error message
    if dbstatus == 'DOWN':
        dbstatus_msg = "Greenplum Database is down"
    elif dbstatus == 'UPGRADE':
        dbstatus_msg = "Greenplum Database is being upgraded"
    elif dbstatus == 'MAINTENANCE':
        dbstatus_msg = "Greenplum Database is in maintenance mode"
    elif dbstatus == 'MASTER_ONLY':
        dbstatus_msg = "Greenplum Database in master only mode"
    elif dbstatus == 'AUTH_ERROR':
        dbstatus_msg = "Webserver database credentials don't appear to work.  Please check configuration"
    elif dbstatus == 'SQL_ERROR':
        dbstatus_msg = "Unable to run SQL on database.  Please check configuration or logs"
    elif dbstatus == 'UNKNOWN':
        dbstatus_msg = "We encountered an unknown error while trying to connect to the database server"

    # return error msg if db inaccessible 
    if dbstatus_msg:
        log.msg('authrole: database not reachable: %s' % dbstatus_msg)
        return dbstatus_msg
    
    (valid, issuper, isoperator, message) = db.get_role(username, password, auth_mech)
    if valid:
        session.user = username                                                   
        session.password = password
        session.loggedin = True 
        session.role['superuser'] = issuper                                       
        session.role['operator'] = isoperator                                       
        session.role['user'] = True                                               
        log.msg("Authenticated user(%s) ok superuser(%s) operator(%s) " % (username, issuper, isoperator))
    else:
        # To clear kerberos session cookie
        db.clearKerberos()
        log.msg("Authentication failed user(%s): %s" % (username, message))
    return message                                                                

def mkerr(code, msg):
    return render.error(web.ctx.fullpath, code, msg)

def api_mkerr(code, msg, gss):
    return render.apierror(web.ctx.fullpath, code, msg, gss)

def timenow():
    return datetime.datetime.now().replace(microsecond=0).isoformat(' ')

class index:
    def POST(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        if i.has_key('username'):
            username = i['username']
        else:
            username = ''
        if i.has_key('password'):
            password = i['password']
        else:
            password  = ''
        if web.ctx.env.has_key('KRB5CCNAME') :
            if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
                db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
        host_and_port = web.ctx.host.split(':', 1)
        if len(host_and_port) == 2:
            host = host_and_port[0]
            port = host_and_port[1]
        else:
            host = web.ctx.host
            port = ''
        return render.index()
  
    def GET(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        host_and_port = web.ctx.host.split(':',1)
        if len(host_and_port) == 2:
            host = host_and_port[0]
            port = host_and_port[1]
        else:
            host = web.ctx.host
            port = ''
        return render.index()

class goods_list:
    def POST(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        if i.has_key('username'):
            username = i['username']
        else:
            username = ''
        if i.has_key('password'):
            password = i['password']
        else:
            password  = ''
        if web.ctx.env.has_key('KRB5CCNAME') :
            if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
                db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
        host_and_port = web.ctx.host.split(':', 1)
        if len(host_and_port) == 2:
            host = host_and_port[0]
            port = host_and_port[1]
        else:
            host = web.ctx.host
            port = ''
        return render.goods_list()
  
    def GET(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        input = web.input()
        cardtypes = pg.CardType.select().order_by(pg.CardType.name)
        cardcategories = pg.CardCategory.select().order_by(pg.CardCategory.name)
        if len(input) == 0:
            sellitems = pg.SellItem.select()
        elif 'starts_with' in input:
            starts_with = input['starts_with']
            sellitems = pg.SellItem.select().join(pg.Card, pg.JOIN.INNER).where(pg.Card.pinying.startswith(starts_with))
        elif 'sort' in input:
            sort = input['sort']
            if sort == 'name':
                sellitems = pg.SellItem.select().join(pg.Card, pg.JOIN.INNER).order_by(pg.Card.pinying)
            elif sort == 'ctime':
                sellitems = pg.SellItem.select().join(pg.Card, pg.JOIN.INNER).order_by(-pg.SellItem.ctime)
            elif sort == 'expire':
                sellitems = pg.SellItem.select().join(pg.Card, pg.JOIN.INNER).order_by(-pg.SellItem.expire)
            else:
                return mkerr(error.BADREQ, "Unknown sort type:%s" % sort)
        return render.goods_list(cardtypes, cardcategories, sellitems)


class goods_info:
    def POST(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        if i.has_key('username'):
            username = i['username']
        else:
            username = ''
        if i.has_key('password'):
            password = i['password']
        else:
            password  = ''
        if web.ctx.env.has_key('KRB5CCNAME') :
            if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
                db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
        host_and_port = web.ctx.host.split(':', 1)
        if len(host_and_port) == 2:
            host = host_and_port[0]
            port = host_and_port[1]
        else:
            host = web.ctx.host
            port = ''
        return render.goods_info()
  
    def GET(self):
        web.header('Content-Type', 'text/html')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        host_and_port = web.ctx.host.split(':',1)
        if len(host_and_port) == 2:
            host = host_and_port[0]
            port = host_and_port[1]
        else:
            host = web.ctx.host
            port = ''

        input = web.input()
        if len(input) == 0:
            return mkerr(error.BADREQ, "good_id not set")
        else:
            good_id = input['card_id']
            card = pg.Card.select().where(pg.Card.id == good_id)
            if card.count() != 1:
                return mkerr(error.BADREQ, "good_id not set")
            card = card[0]
            sellitems = pg.SellItem.select().where(pg.SellItem.card == card.id)
            return render.goods_info(card, sellitems)


class api:
    def __init__(self):
        self.version = gpperfmon_version

    def GET(self):
        global auth_mech
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        tab = []
        for i in range(len(urls)/2-1):
            j = (i+1) * 2 + 1
            tab.append(urls[j])

       
        # To check whether the kerberos ticket present in web context environment or not  
        has_gss = 'False'
        clientSSL_Status = False
        
        try:
            if cleanKrbFile():
                has_gss = 'True'
                auth_mech = 'krb'
            elif (web.ctx.env.has_key('SSL_CLIENT_S_DN_CN')):
                clientSSL_Status = True
                auth_mech = 'pki'
            akeys = db.getapi(tab, session.user, session.password)
        except Exception, err:
            log.msg('Unknown exception in call to api web service: %s' % err)
            return api_mkerr(error.BADREQ, err.__str__(), has_gss)
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to api web service: %s' % err)
            return api_mkerr(error.BADREQ, err, has_gss)

        return render.api(akeys, self.version, has_gss, clientSSL_Status)

class logon:
    def __init__(self):
       # To handle all special characters in username except special character at beginning
       self.sanitize = re.compile('^[\w]+.*')

    # We don't want username/password details saved in the web logs,
    # so do the logon via POST. We've added a simple form for GET that
    # allows testing the logon via a web browser.
    def GET(self):
        # To restrict user to access HTML login page available outside of the application 
        if debug_mode : 
            web.header('Content-Type', 'text/html')
            return render.logon_form()
        else :
            web.ctx.headers = [('Content-Type', 'text/xml')]
            web.ctx.status = '200 OK';
            return mkerr(error.BADREQ, 'You need to have access permission')
             

    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        global sessionTimeout, auth_mech
        i = web.input()
        has_kerb = False
        session.user = ''
        session.role = {}
        session.loggedin = 0
        username = ''
        password = ''
        # To set username and password from kerberos ticket or from post parameters
        if (web.ctx.env.has_key('KRB5CCNAME') and (not i.has_key('username') or i['username'] == '')):
           if os.path.isfile(web.ctx.env['KRB5CCNAME']) :
               db.removeKrbTicket(web.ctx.env['KRB5CCNAME'])
           username = web.ctx.env['REMOTE_USER'].split('@')[0]
           password = 'BOGUS_FOR_KERBEROS'
           has_kerb = True
        elif (web.ctx.env.has_key('SSL_CLIENT_S_DN_CN') and (not i.has_key('username') or i['username'] == '')):
           (dbName, status) = db.getGPDBUsername( web.ctx.env['SSL_CLIENT_S_DN_CN'])
           if status :
              username = dbName
              password = 'BOGUS_FOR_PKI'
           else :
              return mkerr(error.ACCESS_DENIED, 'Client cerificate username not mapped with GPDB username ')
        else :
           if i.has_key('username'):
               username = i['username']
           else:
               return mkerr(error.ACCESS_DENIED, 'Username required')
           if i.has_key('password'):
               password = i['password']
           else:
               return mkerr(error.ACCESS_DENIED, 'Password required')
        
        try:
            s = self.sanitize.search(username)
            if s != None:
                # valid string
                username = s.group()
            else:
                # string contains invalid characters
                return mkerr(error.ACCESS_DENIED, 'Invalid username')
        except:
            return mkerr(error.ACCESS_DENIED, 'Invalid username')

        # authenticate user
        message = ''
        try:
            message = authrole(username, password, auth_mech)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, message)
        
        role = ''
        if session.role['superuser']:
            role = 'superuser'
        elif session.role['operator']:
            role = 'operator'
        else:
            role = 'user'
        csrf_token = generate_csrf_token()
        session.csrf_token = csrf_token
        
        return render.logon(username, 'SUCCESS', role, session.getid(), csrf_token, isAppliance, sessionTimeout)

class logoff:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        
        db.clearKerberos()
        session.loggedin = 0
        session.kill()
        logoffdata = render.logoff(session.user, 'SUCCESS')
        return logoffdata

class config:
    def __init__(self):
        global remote, displayed_server_name, ssl_enabled, verbose, secureDbHealth, dbHealth_PollInterval, maxOpenConnections, sessionTimeout, diskThresholdValue, allowAutoLogin
        
        # Holds the complete configuration
        self.gpperfmon_config = {}

        filename = os.path.join(os.getcwd(), 'conf', 'webserver.conf')
        try:
            # parse configuration file
            cfg = ConfigParser.SafeConfigParser()
            cfg.readfp(open(filename))
        except:
            log.msg("FATAL: Unable to load configuration file: %s\n" % filename)
            sys.exit("FATAL: Unable to load configuration file: %s\n" % filename)

        try:
            dbHealth_PollInterval = cfg.getint("WEB APP", "pollInterval")
        except:
            dbHealth_PollInterval = 30000

        try:
            maxOpenConnections = cfg.getint("WEB APP", "maxConnections")
        except:
            maxOpenConnections = 10

        try:
            secureDbHealth = cfg.getboolean("WEB APP", "secureDbHealth")
        except:
            secureDbHealth = False
            

        try:
            sessionTimeout = cfg.getint("WEB APP", "timeout")
        except:
            sessionTimeout = 1800
        try:
            diskThresholdValue = cfg.getint("WEB APP", "diskThresholdValue")
        except:
            diskThresholdValue = 80

        try:
            allowAutoLogin = cfg.getboolean("WEB APP", "allowAutoLogin")
        except:
            allowAutoLogin = True

        for section in cfg.sections():
            section_elements = {}
            for item in cfg.items(section):
                section_elements[item[0].replace(" ","_")] = item[1]
            self.gpperfmon_config[section.replace(" ","_")] = section_elements


        # look for specific values
        try:
            remote = cfg.getboolean("WEB APP", "remote")
        except:
            remote = False

        try:
            verbose = cfg.getboolean("WEB APP", "verbose")
            if verbose:
                log.setVerbose()
        except:
            verbose = False

        quantum = 15
        if not remote:
            # this logic should really be somewhere else
            try:
                # parse configuration file
                filename = os.path.join(datadir, 'gpperfmon', 'conf', 'gpperfmon.conf')
                gpmmon_cfg = ConfigParser.SafeConfigParser()
                gpmmon_cfg.readfp(open(filename))
                quantum = gpmmon_cfg.getint('GPMMON', 'quantum')
            except:
                log.msg("Using default quantum of 15 seconds. Unable to load configuration file: %s" % filename)
                       
        self.gpperfmon_config['GPMMON'] = {'quantum': quantum}

        # look for specific values
        try:
            displayed_server_name = cfg.get("WEB APP", "server_name")
        except:
            displayed_server_name = gethostname()

        try:
            ssl_enabled = cfg.getboolean("WEB APP", "ssl_enabled")
        except:
            ssl_enabled = False

        global csrf_enabled
        try:
            csrf_enabled = cfg.getboolean("WEB APP", "csrf_protect")
        except:
            csrf_enabled = False

        try:
            ssh_full_path = cfg.get("WEB APP", "ssh_full_path")
            db.set_ssh_full_path(ssh_full_path)
        except:
            ssh_full_path = None

        log.msg("Configuration file: %s" % self.gpperfmon_config)
        log.msg("remote = %s" % remote)
        log.msg("verbose = %s" % verbose)
        log.msg("server_name = %s" % displayed_server_name)
        log.msg("ssl_enabled = %s" % ssl_enabled)
        log.msg("quantum = %s" % quantum)
        log.msg("csrf_enabled = %s" % csrf_enabled)
        log.msg("ssh_full_path = %s" % ssh_full_path)
        log.msg("diskThresholdValue = %s" % diskThresholdValue)
        log.msg("allowAutoLogin = %s" % allowAutoLogin)
        log.msg("setting default GRANTS on tables")
        db.grant_default_permissions()
        log.msg("setting default GRANTS on tables -- done")

        global gpdb_server_name
        gpdb_server_name = pghost = os.environ.get('PGHOST', '127.0.0.1')
        if gpdb_server_name == '127.0.0.1':
            gpdb_server_name = socket.gethostname().split('.')[0]

        global parser
        global productid

        if isAppliance:
            if isV1Appliance:
                log.msg('Running on a V1 DCA')
                try:
                    parser = DcaSetupConfigFileParser(FILEPATH_TO_DCASETUP_SETTINGS, log)
                    parser.readFile()
                except Exception, err:
                    log.msg('Unable to load DCA settings: %s' % err)
                except:
                    log.msg('Unknown error reading DCA settings: %s' % sys.exc_info()[0])

                if not parser.ready:
                    log.msg("FATAL: Unable to load DCA settings file.")
                    sys.exit("\nFATAL: Unable to load DCA settings file.\n")
            else:
                log.msg('Running on a V2 DCA')

                try:
                    cfg = ConfigParser.SafeConfigParser()
                    cfg.readfp(open(FILEPATH_TO_DCASETUP_SETTINGS))
                except Exception, err:
                    log.msg("FATAL: Unable to load DCA settings file %s: %s\n" % (FILEPATH_TO_DCASETUP_SETTINGS, err))
                    sys.exit("FATAL: Unable to load DCA settings file %s: %s\n" % (FILEPATH_TO_DCASETUP_SETTINGS, err))
    
            #Setting the global productid variable
            productid = GPDB_PRODUCT_ID_FILE

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        return render.config(self.gpperfmon_config)
    

class hosts:
    nodes = None

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if hosts.nodes == None:
            # retrieve the list of nodes in the GP DB system
            try:
                hosts.nodes = db.hosts(session.user, session.password)
            except db.GPDBError, errorinfo:
                return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        # return start time
        return render.hosts(hosts.nodes)


class system:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        i = web.input(start='NOW', end='NOW', interval='1min', aggregated='yes', type='all')
        

        if i.type != 'all' and i.type != 'hdw' and i.type != 'hdm' and i.type != 'masters' and i.type != 'segments' and i.type != 'dia':
            return mkerr(error.BADREQ, 'Invalid type parameter specified')
        
        res = None

        try:
            if i.start == 'NOW':
                res = db.system_now(remote, session.user, session.password, i.type)
                i.aggregated = 'no'
                
            else:
                i.aggregated = i.aggregated.lower()
                if not i.aggregated in ['yes', 'no']:
                    return mkerr(error.BADREQ, 'Invalid aggregated parameter')

                if i.end == 'NOW':
                    i.end = timenow()

                # validate the time strings, and check the number of samples
                (status, interval_code, samples) = interval.calc_samples(i.start, i.end, i.interval)
                if not status:
                    return mkerr(error.BADREQ, 'Invalid date parameters')

                if i.aggregated == 'yes' and samples > MAX_AGGREGATED_SAMPLES:
                    return mkerr(error.BADREQ, 'Exceeded maximum number of samples for specified interval')
                elif i.aggregated == 'no' and samples > MAX_NONAGGREGATED_SAMPLES:
                    return mkerr(error.BADREQ, 'Exceeded maximum number of samples for specified interval')

                res = db.system_history(i.start, i.end, interval_code, i.aggregated, session.user, session.password, i.type)

        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())
                
        (tkeys, hkeys, ckeys, tab) = res

        # check if the result set is empty
        if ckeys:
            if i.aggregated == 'yes':
                return render.system_aggregated(i.start, i.end, i.interval, tkeys, ckeys, tab)
            else:
                return render.system_nonaggregated(i.start, i.end, i.interval, tkeys, hkeys, ckeys, tab)
        else:
            return render.system_noresult(i.start, i.end, i.interval)

class diskusagesummary:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input(type='none')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        check_ws = 'diskusagesummary'
        tab = []
        for k in range(len(urls)/2-1):
            j = (k+1) * 2 + 1
            tab.append(urls[j])

        try:
            supported_ws = db.getapi(tab, session.user, session.password)
        except Exception, err:
            log.msg('Unknown exception while checking if the current GPDB version supports the diskusagesummary webservice : %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception while checking if the current GPDB version supports the diskusagesummary webservice : %s' % err)
            return mkerr(error.BADREQ, err)

        if check_ws not in supported_ws:
            return mkerr(error.BADREQ, 'GPDB upgrade required for this functionality')

        
        if i.type != 'hdw' and i.type != 'hdm' and i.type != 'hdc' and i.type != 'hbw' and i.type != 'master' and i.type != 'sdw' and i.type != 'etl' and i.type != 'dia' and i.type != 'all':
            return mkerr(error.BADREQ, 'Invalid type parameter specified')

        interval_code = 7
        try:
            res = db.diskspace_usage('NOW', 'NOW', session.user, session.password, i.type, interval_code, tmp_schema_name, now=True, summary=True, format=True)
        except db.GPDBError, err:
            log.msg('Database error when calling guc WS: %s' % err)
            return mkerr(error.DATA_ACCESS, err.__str__())
        except db.NoDataError, err:
            return mkerr(error.BADREQ, err.__str__())
        except Exception, err:
            log.msg('Unknown exception in call to diskusagesummary web service: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to diskusagesummary web service: %s' % err)
            return mkerr(error.BADREQ, err)

        (tkeys, hkeys, ckeys, fkeys, tab) = res
        return render.diskspaceusagesummary(tkeys, hkeys, ckeys, fkeys, tab)


class diskusagehistory:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input(start='NOW', end='NOW', type='none')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        check_ws = 'diskusagehistory'
        tab = []
        for k in range(len(urls)/2-1):
            j = (k+1) * 2 + 1
            tab.append(urls[j])

        try:
            supported_ws = db.getapi(tab, session.user, session.password)
        except Exception, err:
            log.msg('Unknown exception while checking if the current GPDB version supports the diskusagehistory webservice : %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception while checking if the current GPDB version supports the diskusagehistory webservice : %s' % err)
            return mkerr(error.BADREQ, err)

        if check_ws not in supported_ws:
            return mkerr(error.BADREQ, 'GPDB upgrade required for this functionality')

        
        interval_value = ""
        if i.start == 'NOW':
            if i.type != 'hdw' and i.type != 'hdm' and i.type != 'hdc' and i.type != 'hbw' and i.type != 'master' and i.type != 'sdw' and i.type != 'etl' and i.type != 'dia' and i.type != 'all':
                return mkerr(error.BADREQ, 'Invalid type parameter specified')

            try:
                interval_code = 7
                res = db.diskspace_usage(i.start, i.end, session.user, session.password, i.type, interval_code, tmp_schema_name, now=True, summary=False, format=True)
            except db.GPDBError, err:
                log.msg('Database error when calling guc WS: %s' % err)
                return mkerr(error.DATA_ACCESS, err.__str__())
            except db.NoDataError, err:
                return mkerr(error.BADREQ, err.__str__())
            except Exception, err:
                log.msg('Unknown exception in call to diskusagehistroy web service: %s' % err)
                return mkerr(error.BADREQ, err.__str__())
            except:
                err = sys.exc_info()[0]
                log.msg('Unknown exception in call to diskusagehistory web service: %s' % err)
                return mkerr(error.BADREQ, err)

        else:
            if i.type != 'hdw' and i.type != 'hdm' and i.type != 'hdc' and i.type != 'hbw' and i.type != 'master' and i.type != 'sdw' and i.type != 'etl' and i.type != 'dia':
                return mkerr(error.BADREQ, 'Invalid type parameter specified')

            if i.end == 'NOW':
                i.end = timenow()

            # validate the time strings, and check the number of samples
            (interval_value, status, interval_code, samples) = interval.calc_samples_diskusage(i.start, i.end)
            if not status:
                return mkerr(error.BADREQ, 'Invalid date or interval parameters')

            if samples > MAX_STORAGE_SAMPLES:
                return mkerr(error.BADREQ, 'Exceeded maximum number of samples for specified interval')
            try:
                res = db.diskspace_usage(i.start, i.end, session.user, session.password, i.type, interval_code, tmp_schema_name, now=False, summary=False, format=True)
            except db.GPDBError, err:
                log.msg('Database error when calling guc WS: %s' % err)
                return mkerr(error.DATA_ACCESS, err.__str__())
            except db.NoDataError, err:
                return mkerr(error.BADREQ, err.__str__())
            except Exception, err:
                log.msg('Unknown exception in call to diskusagehistroy web service: %s' % err)
                return mkerr(error.BADREQ, err.__str__())
            except:
                err = sys.exc_info()[0]
                log.msg('Unknown exception in call to diskusagehistory web service: %s' % err)
                return mkerr(error.BADREQ, err)


        (tkeys, hkeys, ckeys, tab) = res
        return render.diskspaceusagehistory(i.start, i.end, interval_value, tkeys, hkeys, ckeys, tab)
 
        
class setquerypriority:
    def __init__(self):
        self.validPriorities=('MIN', 'LOW', 'MEDIUM', 'HIGH', 'MAX')

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(id='', priority='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not isSuperUser():
            return mkerr(error.ACCESS_DENIED, 'You must be a superuser to perform this operation')

        if i.id == '':
            return mkerr(error.BADREQ, "Invalid query ID(empty): " + i.id)

        id_split = i.id.split('-')

        if len(id_split) != 3:
            return mkerr(error.BADREQ, 'Invalid query ID(needs 3 things): ' + i.id)

        # sanitize input against SQL injection attacks
        try:
            for item in id_split:
                int(item)
        except:
            return mkerr(error.BADREQ, 'Invalid query ID (not int)' + i.id + " item: " + item)

        isPriorityValid = False
        pri = i.priority.upper()
        if pri != '':
            for p in self.validPriorities:
                if pri == p:
                    isPriorityValid=True
                    break
        if not isPriorityValid:
            return mkerr(error.BADREQ, "Invalid priority: " + pri)

        commandid = int(id_split[2])
        sessionid = int(id_split[1])
        
        try:
            db.set_query_priority(session.user, session.password, sessionid, commandid, pri)
        except:
            return mkerr(error.DATA_ACCESS, "Failed to set query priority")
        return render.setquerypriority('SUCCESS')

class getquerypriority:
    def __init__(self):
        self.validPriorities=('MIN', 'LOW', 'MEDIUM', 'HIGH', 'MAX')

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        i = web.input(id='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        
        if i.id == '':
            return mkerr(error.BADREQ, "Invalid query ID(empty): " + i.id)

        id_split = i.id.split(',')

        result_list = []
        for queryid in id_split:
            result_list.append(self.get_single_query_priority(queryid) )
        return render.getquerypriority(result_list)

    #This method gets the priority of single query in a greenplum DB
    #Returns a tuple with two (on success) or three strings (on failure) in the format: 
    #(queryid , MIN|LOW|MEDIUM|HIGH|MAX)
    #(queryid , "FAILURE" , "reason for failure") 
    #This tuple format is recognized by the XML template(cancelquery.xml) for formatting the response output
    def get_single_query_priority(self, id):
        id_split = id.split('-')

        if len(id_split) != 3:
            return (id, "FAILURE", "Invalid query ID(needs 3 things) ")

        # sanitize input against SQL injection attacks
        try:
            for item in id_split:
                int(item)
        except:
            return (id, "FAILURE", 'Invalid query ID (not int): ')

        sessionid = int(id_split[1])
        querycount = int(id_split[2])

        try:
            result = db.get_query_priority(session.user, session.password, sessionid, querycount)
        except db.GPDBError, errorinfo:
            return (id, "FAILURE", errorinfo)

        if len(result) == 0:
            return (id, "FAILURE", 'No query running at specified query ID')

        if len(result) != 1:
            return (id, "FAILURE", "Multiple queries with same ID found")

        if result[0].has_key("rqppriority"):
            priority = result[0]['rqppriority']
        pri = priority.upper()
        for p in self.validPriorities:
            if p == pri:
                return (id, pri)
        return (id, "FAILURE", "Invalid priority received: " + priority)

class cancelquery:
    def  __init__(self):
        pass

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(id='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if i.id == '':
            return mkerr(error.BADREQ, "Invalid query ID(empty) ")

        id_split = i.id.split(',')

        result_list = []
        for queryid in id_split:
            result_list.append(self.cancel_single_query(queryid) )

        return render.cancelquery(result_list)

    #This method cancels a single query in a greenplum DB
    #Returns a tuple with two strings on success or three strings on a failure in the format: 
    #(queryid , SUCCESS|FAILURE , "reason for failure") 
    #This tuple format is recognized by the XML template(cancelquery.xml) for formatting the response output
    def cancel_single_query(self, id):

        id_split = id.split('-')

        if len(id_split) != 3:
            return (id, "FAILURE", "Invalid query ID(needs 3 things) ")

        # sanitize input against SQL injection attacks
        try:
            for item in id_split:
                int(item)        
        except:
            return (id, "FAILURE", 'Invalid query ID (not int): ')

        sessionid = int(id_split[1])
        querycount=int(id_split[2])
        result = db.get_procpid(sessionid, querycount)

        if len(result) == 0:
            return (id, "FAILURE", 'No query running at specified query ID')

        if len(result) != 1:
            return (id, "FAILURE", "Multiple procpids found for a single sessionid")
        if result[0].has_key("procpid"):
            procpid = result[0]['procpid']
        try:
            int(procpid)
        except:
            return (id, "FAILURE", "Invalid procpid received: " + str(procpid) ) 

        usename = None
        if result[0].has_key("usename"):
            usename = result[0]['usename']
        if not isOperatorOrSuper() and usename != session.user:
            return (id, "FAILURE", "Non-Privilege user can not cancel query of others")

        try: 
            db.cancel_query(procpid)
        except db.GPDBError, errorinfo:
            return (id, "FAILURE", errorinfo)
        return (id, "SUCCESS")


class queries:
    def __init__(self):
        self.sanitize = re.compile('^\w+$')
        self.valid_status = ['done', 'start', 'submit', 'abort']


    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(start='NOW', end='NOW', status='', textlength='', mintime='', username='', db='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        try:
            if i.textlength != '':
                i.textlength = int(i.textlength)

            # this value is in seconds
            if i.mintime != '':
                i.mintime = int(i.mintime)

            if i.username != '':
                s = self.sanitize.search(i.username)
                if s != None:
                    # valid string
                    i.username = s.group()
                else:
                    # string contains invalid characters
                    return mkerr(error.BADREQ, 'Invalid username')

                # If not authorized, return error if specified search for other user
                if (not isOperatorOrSuper()) and (i.username != session.user):
                    return mkerr(error.NOT_AUTHORIZED, 'Must be superuser or operator to do search of other users')

            elif (not isOperatorOrSuper()):
                # If not authorized, only see my queries
                i.username = session.user

            if i.db != '':
                s = self.sanitize.search(i.db)
                if s != None:
                    # valid string
                    i.db = s.group()
                else:
                    # string contains invalid characters
                    return mkerr(error.BADREQ, 'Invalid database name')
        except:
            return mkerr(error.BADREQ, 'Invalid request parameter(s)')

        # sanitize status input
        # status can be a '|' separated list of multiple values
        if i.status != '':
            i.status = re.split('[\|]', i.status)
            
            for status in i.status:
                if not status in self.valid_status:
                    return mkerr(error.BADREQ, 'Invalid status value')

        res = None

        try:
            if i.start == 'NOW':
                res = db.queries_now(remote, i.status, i.username, i.db, i.textlength, session.user, session.password)
            else:
                # check_valid() sanitizes input against SQL injection attacks 
                try:
                    interval.check_valid(i.start)
                    if i.end != 'NOW':
                        interval.check_valid(i.end)
                except ValueError:
                    return mkerr(error.BADREQ, 'Invalid date parameters')

                res = db.queries_history(i.status, i.start, i.end, i.username, i.mintime, i.db, i.textlength, MAX_QUERIES_PER_SEARCH, session.user, session.password)

        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        (tkeys, ckeys, tab, row_count) = res

        # Did we hit the maximum number of rows for a search?
        if row_count >= MAX_QUERIES_PER_SEARCH:
            hit_row_max = 'true'
        else:
            hit_row_max = 'false'

        return render.queries(i.start, i.end, tkeys, ckeys, tab, row_count, hit_row_max)

    @csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        params = dict()
        if i.has_key('op') and i['op'] == "pastqueries":
            params['op'] = 'pastqueries';
            if i.has_key('lookbackhours'):
                params['lookbackhours'] = i['lookbackhours']

        if i.has_key('op') and i['op'] == "currentqueries":
            params['op'] = 'currentqueries'
            if i.has_key('status'):
                params['status'] = i['status']

        if not params.has_key('op'):
            return mkerr(error.ACCESS_DENIED, 'Unknown operation') 

        try:
            res = db.queries(params, session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.queries_resqueue(res)          


class querydetails:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(id='', realtime='', start='', end='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if i.id == '':
            return mkerr(error.BADREQ, 'Must specify query ID parameter')

        id_split = i.id.split('-')

        if len(id_split) != 3:
            return mkerr(error.BADREQ, 'Invalid query ID')

        # sanitize input against SQL injection attacks 
        try:
            for item in id_split:
                int(item)
        except:
            return mkerr(error.BADREQ, 'Invalid query ID')

        # check_valid() sanitizes input against SQL injection attacks
        try:
            if i.start == '':
                if i.end != '':
                     return mkerr(error.BADREQ, 'Invalid date parameters')
            else:
                interval.check_valid(i.start)

            if i.end == '':
                if i.start != '':
                    return mkerr(error.BADREQ, 'Invalid date parameters')
            else:
                interval.check_valid(i.end)
        except ValueError:
            return mkerr(error.BADREQ, 'Invalid date parameters')

        if i.realtime == '':
            return mkerr(error.BADREQ, 'Missing realtime parameter')

        i.realtime = i.realtime.lower()
        if not i.realtime in ['yes', 'no']:
            return mkerr(error.BADREQ, 'Invalid realtime parameter')

        # Ensure that only superusers can find other's queries
        username = ''
        if (not isOperatorOrSuper()):
            username = session.user
            
        try:
            if i.realtime == 'yes':
                res = db.querydetails_now(remote, id_split[0], id_split[1], id_split[2], username, session.user, session.password)
            else:
                res = db.querydetails_history(id_split[0], id_split[1], id_split[2], username, i.start, i.end, session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        (tkeys, ckeys, tab, row_count) = res

        return render.querydetails(tkeys, ckeys, tab, row_count)



class queryplan:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(id='', realtime='', start='', end='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if i.id == '':
            return mkerr(error.BADREQ, 'Must specify query ID parameter')

        id_split = i.id.split('-')

        if len(id_split) != 3:
            return mkerr(error.BADREQ, 'Invalid query ID')

        # sanitize input against SQL injection attacks
        try:
            for item in id_split:
                int(item)
        except:
            return mkerr(error.BADREQ, 'Invalid query ID')

         # check_valid() sanitizes input against SQL injection attacks
        try:
            if i.start == '':
                if i.end != '':
                    return mkerr(error.BADREQ, 'Invalid date parameters')
            else:
                interval.check_valid(i.start)

            if i.end == '':
                if i.start != '':
                    return mkerr(error.BADREQ, 'Invalid date parameters')
            else:
                interval.check_valid(i.end)
        except ValueError:
            return mkerr(error.BADREQ, 'Invalid date parameters')

        if i.realtime == '':
            return mkerr(error.BADREQ, 'Missing realtime parameter')

        i.realtime = i.realtime.lower()
        if not i.realtime in ['yes', 'no']:
            return mkerr(error.BADREQ, 'Invalid realtime parameter')

        # Ensure that only superusers can find other's queries
        username = ''
        if (not isOperatorOrSuper()):
            username = session.user

        try:
            if i.realtime == 'yes':
                res = db.queryplan_now(id_split[0], id_split[1], id_split[2], username, session.user, session.password)
            else:
                res = db.queryplan_history(id_split[0], id_split[1], id_split[2], username, i.start, i.end, session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        (ckeys, tab, tree, root) = res

        return render.queryplan(i.id, ckeys, tab, tree, root)


'''
return explain result of running queries
'''
class queryexplain:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        input = web.input(id='', realtime='', start='', end='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if input.id == '':
            return mkerr(error.BADREQ, 'Must specify query ID parameter')

        id_split = input.id.split('-')

        if len(id_split) != 3:
            return mkerr(error.BADREQ, 'Invalid query ID')

        # sanitize input against SQL injection attacks
        try:
            for item in id_split:
                int(item)
        except:
            return mkerr(error.BADREQ, 'Invalid query ID')

        # check_valid() sanitizes input against SQL injection attacks
        try:
            if (input.start != '' and input.start != 'NOW'):
                interval.check_valid(input.start)
            if (input.end != '' and input.end != 'NOW'):
                interval.check_valid(input.end)
        except ValueError as e:
            return mkerr(error.BADREQ, 'Invalid date parameters: %s'%(str(e)))

        if input.realtime == '':
            return mkerr(error.BADREQ, 'Missing realtime parameter')

        input.realtime = input.realtime.lower()
        if not input.realtime in ['yes', 'no']:
            return mkerr(error.BADREQ, 'Invalid realtime parameter')

        try:
            res = db.queryexplain(id_split[0], id_split[1], id_split[2], session.user, session.password, input.realtime, input.start, input.end)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        if len(res) == 0:
            if input.realtime == 'yes':
                return mkerr(error.DATA_ACCESS, "No query found in queries_now, refresh your page")
            else:
                return mkerr(error.DATA_ACCESS, "No query found in queries_history")

        # list of dict
        for i in res:
            if "QUERY PLAN" in i:
                i["QUERY PLAN"] = escape(i["QUERY PLAN"])

        return render.queryexplain(res)


class iterator:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(tmid='', ssid='', ccnt='', nid='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if i.tmid == '':
            return mkerr(error.BADREQ, 'missing parameter: "tmid"')
        if i.ssid == '':
            return mkerr(error.BADREQ, 'missing parameter: "ssid"')
        if i.ccnt == '':
            return mkerr(error.BADREQ, 'missing parameter: "ccnt"')
        if i.nid == '':
            return mkerr(error.BADREQ, 'missing parameter: "nid"')

        # sanitize input against SQL injection attacks 
        try:
            i.tmid = int(i.tmid)
            i.ssid = int(i.ssid)
            i.ccnt = int(i.ccnt)
            i.nid = int(i.nid)
        except:
            return mkerr(error.BADREQ, 'invalid query ID')

        try:
            (skeys, ckeys, tab) = db.queryiterator(i.tmid, i.ssid, i.ccnt, i.nid, session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.iterator(i.tmid, i.ssid, i.ccnt, i.nid, skeys, ckeys, tab)



class database:
    @csrf_protected
    def GET(self):
        global db_access_last_time
        global dbstatus, auth_mech
        global DB_STATE_CHECK_INTERVAL
        
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input(start='NOW', end='NOW', interval='1min')
        has_kerb  = cleanKrbFile
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
                
        res = None
        try:
            if i.start == 'NOW':
                res = db.database_now(remote, session.user, session.password)
            else:
                if i.end == 'NOW':
                    i.end = timenow()

                # validate the time strings, and check the number of samples
                (status, interval_code, samples) = interval.calc_samples(i.start, i.end, i.interval)
                if not status:
                    return mkerr(error.BADREQ, 'Invalid date parameters')

                if samples > MAX_AGGREGATED_SAMPLES:
                    return mkerr(error.BADREQ, 'Exceeded maximum number of samples at specified interval')

                res = db.database_history(i.start, i.end, interval_code, session.user, session.password)
            
            if (time.time() - db_access_last_time) > DB_STATE_CHECK_INTERVAL : 
                dbstatus = db.database_state(session.user, session.password, auth_mech)
                db_access_last_time = time.time()
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        if dbstatus == 'DOWN':
            res = None

        if res:
            (tkeys, ckeys, tab) = res
        else:
            tkeys = None
            ckeys = None
            tab = None

        # check if the result set is empty
        if ckeys:
            return render.database(i.start, i.end, i.interval, tkeys, ckeys, tab, dbstatus)
        else:
            return render.database_noresult(i.start, i.end, i.interval, dbstatus)
          

class health:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        res = None
        is_data_current = None
        try:
            is_data_stale = db.is_health_data_stale(gpdb_server_name, session.user, session.password)
            res = db.health()
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        (updatetime, table) = res

        return render.health(updatetime, is_data_stale, table)


class healthdetails:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
    
        i = web.input(hostname='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if i.hostname == '':
            return mkerr(error.BADREQ, 'Must specify hostname parameter')

        res = None
        is_data_current = None 
        try:
            is_data_stale = db.is_health_data_stale(gpdb_server_name, session.user, session.password)
            res = db.healthdetails(i.hostname)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.healthdetails(i.hostname, is_data_stale, res)

# This service can be called without a login
# To check if GPDB is up or not
# this can be used by the GUI to decide weather to display login screen or gpstart screen
class gpdbup:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        database_up = False

        try:
            database_up = db.is_gpdb_running(gpdb_server_name)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.gpdbup(database_up)

class alerts_summary:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        # default limit of 8 results
        if i.has_key('limit'):
            limit = i.limit
            if not limit.isdigit():
                return mkerr(error.BADREQ, 'limit must be an integer.  You specified %s' % i.limit)
        else:
            limit = 8
    
        # default min severity to warning
        if i.has_key('severity'):
            severity = i.severity.upper()
            if severity != 'WARNING' and severity != 'ERROR' and severity != 'FATAL' and severity != 'PANIC': 
                return mkerr(error.BADREQ, 'severity must be log, error, fatal, or panic.  You specified %s' % i.severity)
        else:
            severity = 'FATAL'

        try:
            res = db.alerts_summary(limit, severity, session.user, session.password)
        except db.GPDBError, err:
            log.msg('webserver: database error in call to db.alerts_summary: %s' % err)
            return mkerr(error.DATA_ACCESS, err.__str__())
        except Exception, err:
            log.msg('webserver: unknown exception in call to db.alerts_summary: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to db.alerts_summary: %s' % err)
            return mkerr(error.BADREQ, err)
         
        return render.alerts_summary(res)

class dialhome_summary:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
                    
        # default limit of 8 results
        if i.has_key('limit'):
            limit = i.limit
            if not limit.isdigit():
                return mkerr(error.BADREQ, 'limit must be an integer.  You specified %s' % i.limit)
        else:
            limit = 8
    
        # default min severity to warning
        if i.has_key('severity'):
            severity = i.severity.upper()
            if severity != 'INFO' and severity != 'WARNING' and severity != 'ERROR': 
                return mkerr(error.BADREQ, 'severity must be Info, Warning, or Error.  You specified %s' % i.severity)
        else:
            severity = 'WARNING'

        try:
            res = db.dialhome_summary(limit, severity, session.user, session.password)
        except db.GPDBError, err:
            log.msg('webserver: database error in call to db.dialhome_summary: %s' % err)
            return mkerr(error.DATA_ACCESS, err.__str__())
        except Exception, err:
            log.msg('webserver: unknown exception in call to db.dialhome_summary: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to db.dialhome_summary: %s' % err)
            return mkerr(error.BADREQ, err)
            
        return render.dialhome_summary(res)

class moduledetails:
    @csrf_protected
    def GET(self):
        GPDB_module = 0
        DIA_module  = 0
        HDM_module  = 0
        HDW_module  = 0
        HDC_module  = 0

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        try:
            GPDB_desc = ''
            DIA_desc = ''
            HDM_desc = ''
            HDW_desc = ''
            junk = ''
            HDC_desc = ''
            if isV1Appliance:
                # hack to get the template to work on v1 with new code
                (GPDB_desc, DIA_desc, HDM_desc, HDW_desc, junk, HDC_desc) = db.getmodule_info(session.user, session.password, productid)

                count_segment_hosts = parser.config.segmenthosts
                count_hdm_hosts = parser.config.hdmhosts
                count_hdw_hosts = parser.config.hdwhosts
                count_hbw_hosts = parser.config.hbwhosts
                count_etl_hosts = parser.config.etlhosts

                GPDB_module = count_segment_hosts/(MODULE_SIZE)
                DIA_module  = count_etl_hosts/(MODULE_SIZE)
                HDM_module  = count_hdm_hosts/(MODULE_SIZE)
                HDW_module  = count_hdw_hosts/(MODULE_SIZE)
                HDC_module  = count_hbw_hosts/(MODULE_SIZE)

            elif isAppliance:
                (GPDB_desc, DIA_desc, HDM_desc, HDW_desc, HDC_desc, HBW_desc) = db.getmodule_info(session.user, session.password, productid)
    
                cfg = ConfigParser.SafeConfigParser()
                cfg.readfp(open(FILEPATH_TO_DCASETUP_SETTINGS))
    
                try:
                    count_segment_hosts = cfg.get("host_number", "host_number.segment")
                except Exception, e:
                    count_segment_hosts = 0
    
                try:
                    count_hdm_hosts = cfg.get("host_number", "host_number.hdm")
                except Exception, e:
                    count_hdm_hosts = 0
    
                try:
                    count_hdw_hosts = cfg.get("host_number", "host_number.hdw")
                except Exception, e:
                    count_hdw_hosts = 0
    
                try:
                    count_hdc_hosts = cfg.get("host_number", "host_number.hdc")
                except Exception, e:
                    count_hdc_hosts = 0
    
                try:
                    count_etl_hosts = cfg.get("host_number", "host_number.dia")
                except Exception, e:
                    count_etl_hosts = 0
    
                GPDB_module = int(count_segment_hosts)/(MODULE_SIZE)
                DIA_module  = int(count_etl_hosts)/(MODULE_SIZE_V2)
                HDM_module  = int(count_hdm_hosts)/(MODULE_SIZE_V2)
                HDW_module  = int(count_hdw_hosts)/(MODULE_SIZE)
                HDC_module  = int(count_hdc_hosts)/(MODULE_SIZE_V2)

        except Exception, err:
            log.msg('Unknown exception in call to moduledetails web service: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to moduledetails web service: %s' % err)
            return mkerr(error.BADREQ, err)

        return render.moduledetails(GPDB_module, DIA_module, HDM_module, HDW_module, HDC_module, GPDB_desc, DIA_desc, HDM_desc, HDW_desc, HDC_desc)
 
class guc:
    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if not i.has_key('gucname'):
            return mkerr(error.BADREQ, 'Must specify a GUC name')

        try:
            (master, segment, balanced, min, max, scale) = db.getguc(i.gucname, session.user, session.password)
        except db.GPDBError, err:
            log.msg('Database error when calling guc WS: %s' % err)
            return mkerr(error.DATA_ACCESS, err.__str__())
        except db.NoDataError, err:
            return mkerr(error.BADREQ, err.__str__())
        except Exception, err:
            log.msg('Unknown exception in call to guc web service: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to guc web service: %s' % err)
            return mkerr(error.BADREQ, err)
            
        return render.getguc(master, segment, balanced, i.gucname, min, max, scale)


class roles:
    def __init__(self):
        self.sanitize = re.compile('^\w+$')

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        res = None
        try:
            res = db.roles(session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.roles(res)

    @csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not isSuperUser():
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')

        params = dict()

        if not i.has_key('role'):
            return mkerr(error.ACCESS_DENIED, 'Role name required')
        params['role'] = i['role']

        if not i.has_key('op'):
            return mkerr(error.ACCESS_DENIED, 'Operation is required')


        if i['op'] == 'add2queue':
            if not i.has_key('queuename'):
                return mkerr(error.ACCESS_DENIED, 'Queue name required')
            params['op'] = "add2queue"
            params['queuename'] = i['queuename']
        elif i['op'] == 'deletefromqueue':
            params['op'] = "deletefromqueue"

        if not params.has_key('op'):
            return mkerr(error.ACCESS_DENIED, 'Operation is not supported')

        try:
            db.roles_mod(params, session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.success()

class resqueue:
    def __init__(self):
        self.sanitize = re.compile('^\w+$')

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        res = None
        try:
            res = db.resqueue(session.user, session.password)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.resqueue(res)

    @csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not isOperatorOrSuper():
            return mkerr(error.ACCESS_DENIED, 'You must be superuser or operator to perform this operation')

        params = dict()
        if i.has_key('queuename'):
            params['queuename'] = i['queuename']
        else:
            return mkerr(error.ACCESS_DENIED, 'Queue name required')

        # Default operation
        if not i.has_key('op'):
            return mkerr(error.ACCESS_DENIED, 'Operation is required')

        if i.has_key('active_statements'):
            if not i['active_statements'].isdigit():
                return mkerr(error.BADREQ, 'active_statements must be an integer.  You specified "%s"' % i['active_statements'])
            params['active_statements'] = i['active_statements']

        if i.has_key('memory_limit'):
            params['memory_limit'] = i['memory_limit']

        if i.has_key('max_cost'):
            params['max_cost'] = i['max_cost']

        if i.has_key('min_cost'):
            params['min_cost'] = i['min_cost']

        if i.has_key('priority'):
            params['priority'] = i['priority']

        if i.has_key('cost_overcommit'):
            params['cost_overcommit'] = i['cost_overcommit']

        if i['op'] == 'alter':
            params['op'] = 'alter'
        elif i['op'] == 'delete':
            if not isSuperUser():
                return mkerr(error.ACCESS_DENIED, 'You must be a superuser to delete a resource queue')
            params['op'] = 'delete'
        elif i['op'] == 'create':
            if not isSuperUser():
                return mkerr(error.ACCESS_DENIED, 'You must be a superuser to create a resource queue')
            params['op'] = 'create'

        if not params.has_key('op'):
            return mkerr(error.ACCESS_DENIED, 'Invalid operation specified: %s.  Valid operations are alter, delete, and create.' % i['op'])

        if params['op'] == 'create' and not i.has_key('max_cost') and not i.has_key('active_statements'):
            return mkerr(error.ACCESS_DENIED, 'ERROR: at least one threshold ("ACTIVE_STATEMENTS", "MAX_COST") must be specified when creating a resource queue')
        try:
            db.resqueue_mod(params)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.success()

class gpconfig:
    @csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(token='', guc='', newValue='', masterValue='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if not isSuperUser():
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')

        if i.token == '':
            return mkerr(error.BADREQ, 'Must specify token')

        if i.guc == '':
            return mkerr(error.BADREQ, 'Must specify guc')

        if i.newValue == '':
            return mkerr(error.BADREQ, 'Must specify newValue')

        if i.masterValue == '':
            return mkerr(error.BADREQ, 'Must specify masterValue')

        ok = db.gpconfig(gpdb_server_name, i.token, i.guc, i.newValue, i.masterValue)

        if not ok:
            log.msg("failure trying to submit guc change command")
            return render.gpcontrol_submit(False)

        return render.gpcontrol_submit(True)

    @csrf_protected
    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(plusoutput='no', firstbyte='0')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        
        (args, starttime, token, status, retCode, byte_num, output) = db.get_application_meta_data('gpconfig', i.plusoutput, i.firstbyte)

        if not args:
            return mkerr(error.BADREQ, 'could not locate command metadata')

        return render.gpcontrol_output(args, starttime, token, status, retCode, byte_num, output)


class gpstart:
    #@csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        i = web.input(unixpassword='', token='')

        unixuser = db.getadminuser(gpdb_server_name)
        if unixuser is None:
            return mkerr(error.INTERNAL, 'Failed to get username')
        
        if i.unixpassword == '':
            return mkerr(error.BADREQ, 'Must specify unixpassword')

        if i.token == '':
            return mkerr(error.BADREQ, 'Must specify token')

        errmsg = db.compare_user_with_current_unix_uer(unixuser)
        if errmsg:
            log.msg("Unauthorized gpstart attempt for unix account %s" % unixuser)
            return render.gpcontrol_submit('Auth_Fail')

        # TEST LOGIN
        authorized = db.test_unix_authorization(gpdb_server_name, unixuser, i.unixpassword)

        if not authorized:
            log.msg("Unauthorized gpstart attempt for unix account %s" % unixuser)
            return render.gpcontrol_submit('Auth_Fail')

        ok = db.gpstart(gpdb_server_name, i.token)

        if not ok:
            log.msg("failure trying to start gpstart")
            return render.gpcontrol_submit(False)

        return render.gpcontrol_submit(True)

    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        i = web.input(plusoutput='no', firstbyte='0')

        (args, starttime, token, status, retCode, byte_num, output) = db.get_application_meta_data('gpstart', i.plusoutput, i.firstbyte)

        if not args:
            return mkerr(error.BADREQ, 'could not locate command metadata')

        return render.gpcontrol_output(args, starttime, token, status, retCode, byte_num, output)

class gpstop:
    #@csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(unixuser='', unixpassword='', token='', mode='smart', restart='False')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if i.restart.upper() != 'TRUE' and i.restart.upper() != 'FALSE':
            return mkerr(error.BADREQ, 'You must specify true or false for restart.  You specified %s' % i.restart )
        
        if i.unixuser == '':
            return mkerr(error.BADREQ, 'Must specify unixuser')

        if i.unixpassword == '':
            return mkerr(error.BADREQ, 'Must specify unixpassword')

        if i.token == '':
            return mkerr(error.BADREQ, 'Must specify token')
        
        if i.mode != 'smart' and i.mode != 'fast' and i.mode != 'immediate':
            return mkerr(error.BADREQ, 'Must specify valid mode: "smart",  "fast", or "immediate"')

        errmsg = db.compare_user_with_current_unix_uer(i.unixuser)
        if errmsg:
            log.msg("Unauthorized gpstop attempt for unix account %s" % i.unixuser)
            return render.gpcontrol_submit('Auth_Fail')

        # TEST LOGIN
        authorized = db.test_unix_authorization(gpdb_server_name, i.unixuser, i.unixpassword)

        if not authorized:
            log.msg("Unauthorized gpstop attempt for unix account %s" % i.unixuser)
            return render.gpcontrol_submit('Auth_Fail')

        ok = db.gpstop(gpdb_server_name, i.token, i.mode, i.restart.upper())

        if not ok:
            log.msg("failure trying to execute gpstop")
            return render.gpcontrol_submit(False)

        return render.gpcontrol_submit(True)

    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(plusoutput='no', firstbyte='0')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        
        (args, starttime, token, status, retCode, byte_num, output) = db.get_application_meta_data('gpstop', i.plusoutput, i.firstbyte)

        if not args:
            return mkerr(error.BADREQ, 'could not locate command metadata')

        return render.gpcontrol_output(args, starttime, token, status, retCode, byte_num, output)


class uptime:

    @csrf_protected
    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
 
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        try:
            (gpdbUptime, gpdbVersion, openConnections, serverTime, dcaVersion, dcaSerialNumber) = db.get_uptime(session.user, session.password, isAppliance, tmp_schema_name)
        except Exception, e:
            return mkerr(error.DATA_ACCESS, e.__str__())

        if not gpdbUptime:
            return mkerr(error.DATA_ACCESS, "data not returned from Uptime query")

        parts = gpdbVersion.split("Greenplum Database ")
        if len(parts) > 1:
            gpdbVersion = parts[1]
        parts = gpdbVersion.split(")")
        gpdbVersion = parts[0]

        gpdbDescription = 'Greenplum Status'
        return render.uptime(gpdbUptime, gpdbVersion, dcaVersion, dcaSerialNumber, openConnections, serverTime, gpdbDescription)


class segmentconfig:

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        res = None
        try:
            res = db.segmentconfiguration(session.user, session.password, tmp_schema_name)
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.segmentconfiguration(res)

class segment_config_history:

    @csrf_protected
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(dbid='', limit='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if not isOperatorOrSuper():
            return mkerr(error.ACCESS_DENIED, 'You must be superuser or operator to perform this operation')

        try:
            dbid = int(i.dbid)
            if dbid < 1:
                return mkerr(error.DATA_ACCESS, "Bad dbid specified")
        except:
            return mkerr(error.DATA_ACCESS, "dbid not provided on segment_configuration_history web service")

        try:
            if not i.limit.isdigit():
                return mkerr(error.BADREQ, 'limit must be an integer. You specified %s' % i.limit)
            limit = int(i.limit)
            if limit < 1:
                return mkerr(error.DATA_ACCESS, "Invalid limit value")
        except:
            return mkerr(error.DATA_ACCESS, "Limit not provided on segment_configuration_history web service")

        res = None
        try:
            res = db.segmentconfigurationhistory(session.user, session.password, dbid, limit)
            if res == 0:
                return mkerr(error.DATA_ACCESS, "dbid does not exist")
        except db.GPDBError, errorinfo:
            return mkerr(error.DATA_ACCESS, errorinfo.__str__())

        return render.segmentconfigurationhistory(res)

class gp_prerecoverseg_check:
    @csrf_protected
    def POST(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        i = web.input(token='')
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if not isSuperUser():
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')

        if i.token == '':
            return mkerr(error.BADREQ, 'Must specify token')

        ok = db.check_for_gpdf(gpdb_server_name)
        if not ok:
            return mkerr(error.BADREQ, 'GPDB upgrade required for this functionality')

        ok = db.pre_recoverseg_check(gpdb_server_name, i.token)

        if not ok:
            log.msg("failure trying to execute gp_prerecoverseg_check")
            return render.gpcontrol_submit(False)

        return render.gpcontrol_submit(True)

    @csrf_protected
    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
    
        i = web.input()
        cleanKrbFile()
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')

        if not isSuperUser():
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')

        try:
            pool = WorkerPool()

            serverFSMap = db.genServerFsList(session.user, session.password)
            for hname in serverFSMap:
                hname.strip()
                cmdStr = 'ping -c 1 -W 1 %s' % (hname)
                pool.addCommand( Command(hname, cmdStr, REMOTE, hname) )
            pool.join()
            items = pool.getCompletedItems()
            for i in items:
                if i.results.rc != 0:
                    return mkerr(error.ACCESS_DENIED, "Failure in talking to host %s: All segments must be up to run gprecoverseg" %(i.remoteHost))
        except db.GPDBError, err:
            log.msg('Database error when calling gp_prerecoverseg_check WS: %s' % err)
            return mkerr(error.DATA_ACCESS, err.__str__())
        except db.NoDataError, err:
            return mkerr(error.BADREQ, err.__str__())
        except Exception, err:
            log.msg('Unknown exception in call to gp_prerecoverseg_check web service: %s' % err)
            return mkerr(error.BADREQ, err.__str__())
        except:
            err = sys.exc_info()[0]
            log.msg('Unknown exception in call to gp_prerecoverseg_check web service: %s' % err)
            return mkerr(error.BADREQ, err)
        finally:
            pool.join()
            pool.haltWork()
            pool.joinWorkers()

        (args, starttime, token, status, retCode, byte_num, output) = db.get_application_meta_data('pre_recoverseg_check', 'no', '1')
        
        if not status:
            return render.gp_prerecoverseg(token, True, False, "Metadata of job not available", None, None)

        if status == "RUNNING":
            return render.gp_prerecoverseg(token, True, False, "Running", None, None)

        if status != "DONE":
            return render.gp_prerecoverseg(token, False, True, "Job Failed, see debug log", None, None)

        if retCode is None:
            return render.gp_prerecoverseg(token, False, True, "Return code not availabe, see debug log", None, None)

        if retCode.strip() != "0":
            return render.gp_prerecoverseg(token, False, True, "Job has failed return code, see debug log", None, None)

        output = db.get_pre_recoverseg_output()
        if output is None:
            return render.gp_prerecoverseg(token, False, True, "Output from command not availabe, see debug log", None, None)

        if not db.check_pre_recoverseg_output(output):
            return render.gp_prerecoverseg(token, False, True, "Job did not have expected output, see debug log", None, None)

        (segments, devices) = db.parse_pre_recoverseg(output)

        return render.gp_prerecoverseg(token, False, False, "ok", segments, devices)

class getadminusername:
    
    def GET(self):

        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')

        cleanKrbFile()
        username = db.getadminuser(gpdb_server_name)
        
        if username is None:
            return mkerr(error.DATA_ACCESS, "Failed to get owner of database")
        
        return render.getadminusername(username)

class gpwlm_throttle:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        i = web.input()
        if i.has_key('query_id'):
            query_id = i['query_id']
        else:
            return mkerr(error.BADREQ, 'query_id required')
        if i.has_key('percent'):
             percent = i['percent']
        else:
            return mkerr(error.BADREQ, 'percent required')
        # the query ID displayed in the UI is
        # <timestamp>-<session id>-<command count>
        # e.g. 0123456789-1234-12
        if not re.match('^\d+-\d+-\d+$', query_id):
            return mkerr(error.BADREQ, 'malformed query id')
        query_id_arr = query_id.split('-')
        session_id = query_id_arr[1]
        command_count = query_id_arr[2]
        if not re.match('^\d*\.?\d+$', percent):
            return mkerr(error.BADREQ, 'malformed percent')
        # the command count is no longer used, but may be needed again in the future.
        # we can leave the logic here for the time being
        expression = 'transient gpcc%s host:throttle_pid(cpu_pct = %s) when host:session_id:pid:session_id = %s and host:pid:cpu_util > %s' % (query_id, percent, session_id, percent)
        # first, attempt to add the rule
        (retcode, stdout, stderr) = run_gpwlm('--rule-add="%s"' % expression)
        if retcode != 0:
            log.msg("Throttle add command failed with exit code %s: %s" % (retcode, stderr))
            # if rule add failes there may be a rule in place already. attempt to modify the existing rule
            (retcode, stdout, stderr) = run_gpwlm('--rule-modify="%s"' % expression)
            if retcode != 0:
                log.msg("Throttle modify command failed with exit code %s: %s" % (retcode, stderr))
        return render.gpwlm_throttle(retcode)

class gpwlm_unthrottle:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        i = web.input()
        if i.has_key('query_id'):
            query_id = i['query_id']
        else:
            return mkerr(error.BADREQ, 'query_id required')
        if not re.match('^\d+-\d+-\d+$', query_id):
            return mkerr(error.BADREQ, 'malformed query id')
        (retcode, stdout, stderr) = run_gpwlm('--rule-delete=\'gpcc%s\'' % query_id)
        if retcode != 0:
            log.msg("Throttle delete command failed with exit code %s: %s" % (retcode, stderr))
        return render.gpwlm_unthrottle(retcode)

class gpwlm_get_throttled_queries:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        (retcode, stdout, stderr) = run_gpwlm('--rule-show=all')
        if retcode != 0:
            log.msg("Throttling list command failed with exit code %s: %s" % (retcode, stderr))
        queries = list()
        percents = list()
        for rule in stdout.split('\n'): # iterate over all rules
            if string.find(rule, "gpcc") != -1: # this rule applies to us
                queries.append(rule.split()[0][4:]) # get query ID
                percents.append(rule.split()[11]) # get percent
        return render.gpwlm_get_throttled_queries(queries, percents)

class rule_add:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not session.role['superuser']:
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')
        i = web.input()
        if i.has_key('name'):
            name = i['name']
        else:
            return mkerr(error.BADREQ, 'name required')
        if i.has_key('expression'):
            expression = i['expression']
        else:
            return mkerr(error.BADREQ, 'expression required')
        (retcode, stdout, stderr) = run_gpwlm('--rule-add="%s %s"' % (name, expression))
        if retcode != 0:
            log.msg('Failed to create rule \'%s %s\'' % (name, expression))
        return render.rule_add(retcode)

class rule_delete:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not session.role['superuser']:
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')
        i = web.input()
        if i.has_key('name'):
            name = i['name']
        else:
            return mkerr(error.BADREQ, 'name required')
        (retcode, stdout, stderr) = run_gpwlm('--rule-delete="%s"' % name)
        if retcode != 0:
            log.msg('Failed to delete rule \'%s\'' % name)
        return render.rule_delete(retcode)

class rule_modify:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        if not session.role['superuser']:
            return mkerr(error.ACCESS_DENIED, 'You must be a super user to perform this operation')
        i = web.input()
        if i.has_key('name'):
            name = i['name']
        else:
            return mkerr(error.BADREQ, 'name required')
        if i.has_key('expression'):
            expression = i['expression']
        else:
            return mkerr(error.BADREQ, 'expression required')
        (retcode, stdout, stderr) = run_gpwlm('--rule-modify="%s %s"' % (name, expression))
        if retcode != 0:
            log.msg('Failed to modify rule \'%s %s\'' % (name, expression))
        return render.rule_modify(retcode)

class autologininfo:
    def GET(self):
        web.header('Content-Type', 'text/xml')
        web.header('Cache-Control', 'no-store')
        if not session.loggedin:
            return mkerr(error.ACCESS_DENIED, 'You must be logged on to perform this operation')
        return render.autoLogon(session.user, session.password, session.csrf_token, allowAutoLogin) 


def memory_check(threshold):
    memory_bytes = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if memory_bytes >= threshold:
        log.msg("webserver memory usage is more than %s, restarting..." % (memory_bytes))
        sys.exit(1)
    else:
        log.msg("webserver memory usage is %s" % (memory_bytes))

def defensive_check(check_time):
    log.msg("starting defensive check thread, check time is %s" % check_time)

    while True:
        time.sleep(check_time) 
        memory_check(2 * 1024 * 1024 * 1024)    # 2GB

def init_session(app, instance_name, store_path, timeout, secure):
    web.config.session_parameters.timeout = timeout 
    web.config.session_parameters.secure = secure

    store = web.session.DiskStore(store_path)
    initializer = { 'user': '', 'password' : '', 'role': {}, 'loggedin': 0, 'gpperfmon_instance_name': instance_name }
    return web.session.Session(app, store = store, initializer = initializer)
     
if __name__ == '__main__':
    log = gplog.GpWebLogger(os.getcwd() + "/runtime/logs/webserver.log")
    log.msg("webserver started")
    db.set_logger(log)

    config()
    app = web.application(urls, locals())
    app.notfound = page_not_found
    app.internalerror = web.debugerror
    #app.internalerror = internal_error
    
    store_path = tempfile.mkdtemp(dir=os.path.join(os.getcwd(), 'runtime', 'sessions'))
    #session = init_session(app, instance_name, store_path, sessionTimeout, ssl_enabled)
    
    render = web.template.render('./templates/', cache=False)

    thread.start_new_thread(defensive_check, (ONE_DAY_IN_SECONDS, ) )

    app.run()
