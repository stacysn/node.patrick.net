create table comments (
    comment_id         bigint(20) unsigned not null auto_increment,
    comment_author     bigint(20) unsigned not null,
    comment_address_id bigint(20) unsigned not null,
    comment_created    datetime            not null,
    comment_modified   timestamp           not null default current_timestamp on update current_timestamp,
    comment_content    text                not null,
    comment_likes      bigint(20) unsigned not null default 0,
    comment_dislikes   bigint(20) unsigned not null default 0,
    comment_approved   bigint(20) unsigned not null default 1,
    primary key                  (comment_id),
    key comment_approved_index   (comment_approved),
    key comment_address_id_index (comment_address_id),
    key comment_author_index     (comment_author),
    fulltext key comment_content_index (comment_content)
) engine=myisam; # necessary for fulltext index
