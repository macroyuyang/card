create external web table INSTANCE_SCHEMA_NAME.fsmap (host varchar(255), mount varchar(255), oid bigint) execute '$GPPERFMONHOME/bin/gpgenfsmap.py 2> /dev/null || true' on master format 'text' (delimiter ' ' NULL as 'null');
grant all on table INSTANCE_SCHEMA_NAME.fsmap to public;

create table INSTANCE_SCHEMA_NAME.fsmapcache as select * from INSTANCE_SCHEMA_NAME.fsmap group by host, mount, oid;
grant all on table INSTANCE_SCHEMA_NAME.fsmapcache to public;

