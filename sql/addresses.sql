create table addresses (
    address_id            bigint(20) unsigned not null auto_increment,
    address_num_street    varchar(128)        not null,
    address_apt           varchar(6),
    address_zip           varchar(5)          not null,
    address_latitude      float(10,6),
    address_longitude     float(10,6),
    address_validated     bigint(20) unsigned          default 0,
    address_comment_count bigint(20) unsigned          default 0,
    address_views         bigint(20) unsigned          default 0,
    address_modified      timestamp           not null default current_timestamp on update current_timestamp,
    primary key                (address_id),
    unique  key address_unique (address_num_street, address_apt, address_zip),
    key address_modified_index (address_modified)
);
