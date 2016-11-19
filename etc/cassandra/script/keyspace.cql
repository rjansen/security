create keyspace fivecolors with replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
create user fivecolors with password 'fivecolors' nosuperuser;
grant all permissions on keyspace fivecolors to fivecolors;