drop schema if exists INSTANCE_SCHEMA_NAME cascade;
create schema INSTANCE_SCHEMA_NAME;
grant all on schema INSTANCE_SCHEMA_NAME to public;

CREATE TYPE INSTANCE_SCHEMA_NAME.seg_config_results AS (
    dbid   integer,
    content  integer,
    role  text,
    preferred_role  text,
    mode  text,
    status  text,
    port  integer,
    hostname  text,
    address  text,
    replication_port  integer,
    recovery_done integer,
    recovery_total integer,
    count bigint,
    latest_event timestamp with time zone,
    latest_event_description text
);

CREATE FUNCTION INSTANCE_SCHEMA_NAME.perfmon_schema_version()
    RETURNS int
AS $$
    return 1

$$ LANGUAGE plpythonu;
GRANT ALL on FUNCTION INSTANCE_SCHEMA_NAME.perfmon_schema_version() to PUBLIC;


CREATE FUNCTION INSTANCE_SCHEMA_NAME.segment_configuration_recovery (dbid integer, content integer, role text, preferred_role text, mode text, status text, port integer, hostname text, address text, replication_port integer, count bigint, latest_event timestamp with time zone, latest_event_description text)
    RETURNS INSTANCE_SCHEMA_NAME.seg_config_results
AS $$
    class seg_config_results:
        def __init__ (self, dbid, content, role, preferred_role, mode, status, port, hostname, address, replication_port, recovery_done, recovery_total, count, latest_event, latest_event_description):
            self.dbid = dbid
            self.content = content
            self.role = role
            self.preferred_role = preferred_role
            self.mode = mode
            self.status = status
            self.port = port
            self.hostname = hostname
            self.address = address
            self.replication_port = replication_port
            self.recovery_done = recovery_done
            self.recovery_total = recovery_total
            self.count = count
            self.latest_event = latest_event
            self.latest_event_description = latest_event_description

    resyncNumCompleted = None
    resyncTotalToComplete = None

    global mode
    if status == 'd':
        mode = 'n'

    if mode == 'r' and role == 'p':
        import subprocess
        cmd = "gp_primarymirror -p %s -h %s -n 1" % (port, address)
        p = subprocess.Popen(cmd, shell = True, stdin=subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        result = p.communicate(input="getMirrorStatus\n")
        
        for line in result[1].splitlines():
            fields = line.strip().split(":")
            if len(fields) != 2:
                continue
            if fields[0] == 'resyncNumCompleted':
                try:
                    resyncNumCompleted = int(fields[1])
                except:
                    resyncNumCompleted = None
            elif fields[0] == 'resyncTotalToComplete':
                try:
                    resyncTotalToComplete = int(fields[1])
                except:
                    resyncTotalToComplete = None
        
    return seg_config_results(dbid, content, role, preferred_role, mode, status, port, hostname, address, replication_port, resyncNumCompleted, resyncTotalToComplete, count, latest_event, latest_event_description)

$$ LANGUAGE plpythonu;
GRANT ALL ON FUNCTION INSTANCE_SCHEMA_NAME.segment_configuration_recovery(int, int, text, text, text, text, int, text, text, int, bigint, timestamp with time zone, text) to PUBLIC;

create external web table INSTANCE_SCHEMA_NAME.dca_appliance_version (version varchar(255)) execute 'cat /etc/gpdb-appliance-version 2> /dev/null || true' on master format 'text' (delimiter '|' NULL as 'null');
grant all on table INSTANCE_SCHEMA_NAME.dca_appliance_version to public;

create external web table INSTANCE_SCHEMA_NAME.dca_serial_number (version varchar(255)) execute 'cat /opt/greenplum/serialnumber 2> /dev/null || true' on master format 'text' (delimiter '|' NULL as 'null');
grant all on table INSTANCE_SCHEMA_NAME.dca_serial_number to public;

create external web table INSTANCE_SCHEMA_NAME.dca_hostmapping (dcahostname varchar(255), customerhostname varchar(255), hosttype varchar(255)) execute 'cat /opt/dca/etc/dca_setup/hostmapping.state 2> /dev/null || true' on master format 'text' (delimiter '|' NULL as 'null');
grant all on table INSTANCE_SCHEMA_NAME.dca_hostmapping to public;

-- Create a UDF to create gp_log_master_ext table if not exists.
CREATE OR REPLACE FUNCTION create_master_log_tbl() RETURNS void AS
$$
BEGIN
        IF EXISTS (SELECT * FROM   pg_catalog.pg_tables WHERE  schemaname = 'public' AND tablename  = 'gp_log_master_ext') THEN
                NULL;  
        ELSE
                CREATE EXTERNAL WEB TABLE public.gp_log_master_ext (LIKE gp_toolkit.__gp_log_master_ext) EXECUTE E'find $GP_SEG_DATADIR/pg_log/ -name "gpdb*.csv" | sort -r | head -n 2 | xargs cat' ON MASTER FORMAT 'csv' (delimiter E',' null E'' escape E'"' quote E'"') ENCODING 'UTF8';
        END IF;

END;
$$ LANGUAGE plpgsql;
grant all on function create_master_log_tbl() to public;

SELECT create_master_log_tbl();
