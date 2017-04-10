create table countries (
    country_name     varchar(40)          not null,
    country_registry varchar(20)          not null,
    country_start    bigint(20)  unsigned not null,
    country_end      bigint(20)  unsigned not null,
    country_assigned bigint(20)  unsigned not null,
    country_evil     bigint(20)  unsigned not null default 0,
    key country_start_index (country_start),
    key country_end_index   (country_end)
);
