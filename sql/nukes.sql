create table nukes (
    nuke_date       datetime,
    nuke_ip_address varchar(16) not null,
    nuke_email      varchar(100),
    nuke_username   varchar(250),
    nuke_country    varchar(40),
    unique key nuke_ip_address (nuke_ip_address)
);
