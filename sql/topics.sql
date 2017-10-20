create table topics (
    topic   varchar(32) not null primary key,
    admin   bigint(20) unsigned,  
    deputy1 bigint(20) unsigned,
    deputy2 bigint(20) unsigned,
    deputy3 bigint(20) unsigned,
    css_url varchar(256)
);
