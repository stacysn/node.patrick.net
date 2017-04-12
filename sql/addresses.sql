create table addresses (
    address_id            bigint(20) unsigned not null auto_increment,
    address_flags         bigint(20) unsigned not null default 0,
    address_num_street    varchar(128)        not null,
    address_apt           varchar(6),
    address_zip           varchar(5)          not null,
    address_latitude      float(10,6),
    address_longitude     float(10,6),
    address_author        bigint(20)          not null,
    address_created       datetime            not null,
    address_modified      timestamp           not null default current_timestamp on update current_timestamp,
    address_comment_count bigint(20)          not null default 0,
    address_views         int(11)             not null default 0,
    primary key                (address_id),
    unique  key address_unique (address_num_street, address_apt, address_zip),
    key address_modified_index (address_modified)
);
