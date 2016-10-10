create keyspace fivecolors_test with replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
create user fivecolors_test with password 'fivecolors_test' nosuperuser;
grant all permissions on keyspace fivecolors_test to fivecolors_test;