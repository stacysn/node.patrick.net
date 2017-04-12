create table zips (
    zip_code         varchar(5),
    zip_state        varchar(2),
    zip_city         varchar(80),
    zip_longitude    float(10,6),
    zip_latitude     float(10,6),
    zip_pop1990      bigint(20) unsigned,
    primary key (zip_code)
);
# import zips.txt like this:
#   mysql -uroot -ppasswd --local-infile -D whatdidyoubid -A
# you need that --local-infile to avoid "ERROR 1148 (42000): The used command is not allowed with this MySQL version" with the following:
#   load data local infile "zips.txt" into table bad_zips
#   fields terminated by ','
#   optionally enclosed by '"'
#   lines terminated by '\n'
#   (zip_code, zip_state, zip_city, zip_longitude, zip_latitude, zip_pop1990);
