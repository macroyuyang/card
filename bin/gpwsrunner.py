#!/usr/bin/env python

'''
USAGE:   gpwsrunner.py 
            --commandline "COMMAND LINE" 
            --directory DIR 
            --application APPNAME 
            --token TOKEN 
            [--group GROUP] 
            [--remotehost HOSTNAME]
            [--nodeamon]
            [--nostreaming]
'''

import os, sys, time, fcntl, subprocess, tempfile

try:
    from optparse import Option, OptionParser 
    from gppylib.gpparseopts import OptParser, OptChecker
except ImportError, e:    
    sys.exit('Cannot import modules.  Please check that you have sourced greenplum_path.sh.  Detail: ' + str(e))

LAST_APPLICATION_KEYWORD = "LastApplication"

g_options = None
g_gphome = os.environ.get('GPHOME')
g_pgport = os.environ.get('PGPORT')
g_master_data_directory = os.environ.get('MASTER_DATA_DIRECTORY')
g_gpperfmonhome = os.environ.get('GPPERFMONHOME')
g_start_time = None
g_application_metafile = None
g_application_outfile = None
g_application_lockfile = None
g_application_lockfile_fd = None
g_application_logfile = None
g_group_metafile = None
g_group_lockfile = None
g_group_lockfile_fd = None

class RunnerStatus():
    RUNNER_STATUS_RUNNING=1
    RUNNER_STATUS_ABORTED=2
    RUNNER_STATUS_DONE=3

    
def setglobals():

    global g_start_time, g_gphome, g_gpperfmonhome, g_master_data_directory, g_pgport
    global g_application_metafile, g_application_outfile, g_application_lockfile, g_group_metafile, g_group_lockfile, g_application_logfile

    g_start_time = time.strftime("%d %b %Y %H:%M", time.localtime())

    g_application_metafile = "%s/%s.metadata" % (g_options.directory, g_options.application)
    g_application_outfile = "%s/%s.output" % (g_options.directory, g_options.application)
    g_application_lockfile = "%s/%s.lock" % (g_options.directory, g_options.application)
    g_application_logfile = "%s/%s.log" % (g_options.directory, g_options.application)

    g_group_metafile = "%s/%s.metadata" % (g_options.directory, g_options.group)
    g_group_lockfile = "%s/%s.lock" % (g_options.directory, g_options.group)

def clearapplicatonlog():
    try:
        fd = open(g_application_logfile, "w")
        fd.close()
    except:
        pass

def applicationlog(msg):
    try:
        current = time.strftime("%d %b %Y %H:%M", time.localtime())
        fd = open(g_application_logfile, "a")
        fd.write("%s: %s\n" % (current, msg))
        fd.close()
    except:
        pass

def parseargs():

    evs = ((g_gphome, 'GPHOME'), (g_gpperfmonhome, 'GPPERFMONHOME'), (g_master_data_directory, 'MASTER_DATA_DIRECTORY'))

    for (var, desc) in evs:
        if not var:
            print >> sys.stderr, "$%s must be set" % desc
            sys.exit(1)

    global g_options

    parser = OptParser(option_class=OptChecker)
    parser.remove_option('-h')
    parser.add_option('-h', '-?', '--help', action='store_true')
    parser.add_option('-c', '--commandline', type='string')
    parser.add_option('-d', '--directory', type='string')
    parser.add_option('-g', '--group', type='string')
    parser.add_option('-a', '--application', type='string')
    parser.add_option('-t', '--token', type='string')
    parser.add_option('-r', '--remotehost', type='string')
    parser.add_option('--nodaemon', action='store_true')
    parser.add_option('--nostreaming', action='store_true')
    (g_options, args) = parser.parse_args()

    if g_options.help:
        print __doc__
        sys.exit(0)

    mustHaves = ['commandline', 'directory', 'application', 'token']
    for clo in mustHaves:
        if not getattr(g_options, clo):
            print >> sys.stderr, "Missing required command line attribute: --%s" % clo
            sys.exit(1)

def daemonize():
    try:
        pid = os.fork()
    except OSError, e:
        applicationlog("Failed to fork: %s" % e.__str__())
        sys.exit(1)
    except:
        applicationlog("Failed to fork")
        sys.exit(1)

    # if parent
    if pid:
        os._exit(0)

    try:
        os.setsid()
    except OSError, e:
        applicationlog("Failed to setsid: %s" % e.__str__())
        sys.exit(1)
    except:
        applicationlog("Failed to setsid")
        sys.exit(1)

    # FORK AGAIN
    try:
        pid = os.fork()
    except OSError, e:
        applicationlog("Failed second fork: %s" % e.__str__())
        sys.exit(1)
    except:
        applicationlog("Failed second fork")
        sys.exit(1)

    # if parent
    if pid:
        os._exit(0)

    os.chdir(g_gphome)

def updateGroupMetadata():
    metafilebak = "%s.bak" % g_group_metafile

    # we first move the existing file using an atomic operation to a backup file
    # clients reading the existing file should be uninterrupted by this.
    try:
        os.rename(g_application_metafile, metafilebak)
    except:
        pass

    try:
        fd = open(g_group_metafile, "w")
        fd.write("%s %s\n" % (LAST_APPLICATION_KEYWORD, g_options.application))
        fd.write("CommandLine %s\n" % g_options.commandline)
        fd.write("StartTime %s\n" % g_start_time)
        fd.write("Token %s\n" % g_options.token)
        fd.close()
    except Exception, e:
        applicationlog("Failed writing file %s: %s" % (g_group_metafile, e.__str__()))
    except:
        applicationlog("Failed writing file %s" % g_group_metafile)
        
def updateApplicationMetadata(status, returnCode=None):

    statusString = None
    metafilebak = "%s.bak" % g_application_metafile

    if status == RunnerStatus.RUNNER_STATUS_RUNNING:
        statusString = "RUNNING"
    elif status == RunnerStatus.RUNNER_STATUS_DONE:
        statusString = "DONE"
    else:
        statusString = "ABORTED"
        
    # we first move the existing file using an atomic operation to a backup file
    # clients reading the existing file should be uninterrupted by this.
    try:
        os.rename(g_application_metafile, metafilebak)
    except:
        pass

    try:
        fd = open(g_application_metafile, "w")
        fd.write("CommandLine %s\n" % g_options.commandline)
        fd.write("StartTime %s\n" % g_start_time)
        fd.write("Token %s\n" % g_options.token)
        fd.write("Status %s\n" % statusString)

        if returnCode is not None:
            fd.write("ReturnCode %s\n" % returnCode)

        fd.close()
    except Exception, e:
        applicationlog("Failed writing file %s: %s" % (g_application_metafile, e.__str__()))
    except:
        applicationlog("Failed writing file %s" % g_application_metafile)
        

def lockApplication():

    global g_application_lockfile_fd
    g_application_lockfile_fd = open(g_application_lockfile, "w")

    try:
        fcntl.lockf(g_application_lockfile_fd.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
    except:
        sys.exit(1)

    clearapplicatonlog()
    applicationlog("obtained application lock")


# MUST ONLY BE CALLED WITH APPLICATIONLOCK
def updateApplicationWithError(msg):

    updateApplicationMetadata(RunnerStatus.RUNNER_STATUS_ABORTED)

    try:
        fd = open(g_application_outfile, "w")
        fd.write("%s\n" % msg)
        fd.close()
    except:
        pass


# MUST BE CALLED AFTER lockApplication 
# APPLICATION LOCK IS HELD AT THIS POINT
def lockGroup():

    global g_group_lockfile_fd
    g_group_lockfile_fd = open(g_group_lockfile, "w")

    try:
        fcntl.lockf(g_group_lockfile_fd.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
        applicationlog("obtained group lock")
        return # ok we got the lock, lets get out of here now :)
    except:
        pass

    activeApplication = "UnknownApplication"

    # GET CONFLICTING APPLICATION
    try:
        fd = open(g_group_metafile)
        for line in fd:
            applicationlog(line)
            if not line.startswith(LAST_APPLICATION_KEYWORD):
                continue
            fields = line.strip().split()
            if len(fields) <= 1:
                continue
            activeApplication = " ".join(fields[1:])
            break
        fd.close()
    except Exception, e:
        applicationlog(e.__str__())
        applicationlog("exception reading group meta file")
    except:
        applicationlog("exception reading group meta file")

    updateApplicationWithError("Can not run because %s is currently running" % activeApplication)

    applicationlog("Could not get the group lock")
    sys.exit(1)

def getFullCommand(remotehost, gphome, gpperfmonhome, pgport, master_data_directory, commandline):
    if remotehost:
        pgport_env = ('PGPORT=%s' % pgport) if pgport  else '' 
        return 'ssh %s "source %s/greenplum_path.sh; source %s/gpcc_path.sh; %s MASTER_DATA_DIRECTORY=%s %s"' % (remotehost, gphome, gpperfmonhome, pgport_env, master_data_directory, commandline)
    else:
        return commandline

def runCommand():

    fd = None

    if not g_options.nostreaming: 
        try:
            fd = open(g_application_outfile, "w")
        except:
            applicationlog("error opening file: %s" % g_application_outfile)
    else:
        try:
            strmTmpfile = g_application_outfile + "_tmp"
            fd = open(strmTmpfile, "w")

        except Exception, e:
            applicationlog("error creating tmp dir on master %s" % e.__str__())

    if not fd:
        applicationlog("No output file to write to")
        sys.exit(1)

    full_command = getFullCommand(g_options.remotehost, g_gphome, g_gpperfmonhome, g_pgport, g_master_data_directory,  g_options.commandline)

    applicationlog("run command: %s" % full_command)

    proc = subprocess.Popen(full_command, shell = True, executable='/bin/bash', stdout=fd, stderr=fd)

    updateApplicationMetadata(RunnerStatus.RUNNER_STATUS_RUNNING)

    exitStatus = os.waitpid(proc.pid, 0)[1]

    try:
        fd.close()
    except:
        pass

    status = RunnerStatus.RUNNER_STATUS_DONE

    applicationlog("Command done")

    if exitStatus:
        retCode = exitStatus >> 8
    else:
        retCode = 0
        if g_options.nostreaming:
            applicationlog("rename %s to %s" % (strmTmpfile, g_application_outfile)) 
            os.rename(strmTmpfile, g_application_outfile)

    updateApplicationMetadata(status, retCode)


if __name__ == '__main__':

    parseargs()

    setglobals()

    if not g_options.nodaemon:
        daemonize()

    lockApplication()

    if g_options.group:
        lockGroup()
        updateGroupMetadata()

    runCommand()
