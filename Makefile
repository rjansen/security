NAME 			:= security
BIN         	:= $(NAME)
REPO        	:= farm.e-pedion.com/repo/$(NAME)
BUILD       	:= $(shell openssl rand -hex 10)
VERSION     	:= $(shell if [ -f version ]; then awk '{printf $1}' < version; else openssl rand -hex 5; fi)
MAKEFILE    	:= $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))
BASE_DIR    	:= $(shell cd $(dir $(MAKEFILE)); pwd)
PKGS        	:= $(shell go list ./... | grep -v /vendor/)
ETC_DIR 		:= ./etc
CONF_DIR 		:= $(ETC_DIR)/$(NAME)
CONF_TYPE 		:= yaml
ENV 			?= local

#Test and Benchmark Parameters
TEST_PKGS ?= 
COVERAGE_FILE := $(NAME).coverage
COVERAGE_HTML := $(NAME).coverage.html
PKG_COVERAGE := $(NAME).pkg.coverage
TEST_ETC_DIR := ./test/etc
TEST_CONF_DIR := $(TEST_ETC_DIR)/$(NAME)
TEST_CONF_TYPE := yaml
TEST_CONF := $(TEST_CONF_DIR)/$(NAME).$(TEST_CONF_TYPE)

#Persistence parameters
DB ?= cassandra
DB_USER ?= fivecolors_test
DB_PWD ?= fivecolors_test
DB_CATALOG ?= fivecolors_test
#Cassandra parameters
TEST_CQL_DIR := $(TEST_ETC_DIR)/cassandra/script
CASSANDRA_KEY_FILE := $(TEST_CQL_DIR)/keyspace.cql
CASSANDRA_DROP_KEY_FILE := $(TEST_CQL_DIR)/drop_keyspace.cql
CASSANDRA_SCHEMA_FILE := $(TEST_CQL_DIR)/fivecolors_test.cql
CASSANDRA_DROP_SCHEMA_FILE := $(TEST_CQL_DIR)/drop_fivecolors_test.cql
CASSANDRA_DATA_FILE := $(TEST_CQL_DIR)/data_fivecolors_test.cql
#Cassandra parameters
TEST_MONGO_DIR := $(TEST_ETC_DIR)/mongo/script
MONGO_DB_FILE := $(TEST_MONGO_DIR)/database.mongo
MONGO_DROP_DB_FILE := $(TEST_MONGO_DIR)/drop_database.mongo
MONGO_SCHEMA_FILE := $(TEST_MONGO_DIR)/fivecolors_test.js
MONGO_DROP_SCHEMA_FILE := $(TEST_MONGO_DIR)/drop_fivecolors_test.js
MONGO_DATA_FILE := $(TEST_MONGO_DIR)/data_fivecolors_test.js
#MySql parameters
TEST_MYSQL_DIR := $(TEST_ETC_DIR)/mysql/script
MYSQL_DB_FILE := $(TEST_MYSQL_DIR)/database.sql
MYSQL_DROP_DB_FILE := $(TEST_MYSQL_DIR)/drop_database.sql
MYSQL_SCHEMA_FILE := $(TEST_MYSQL_DIR)/fivecolors_test.sql
MYSQL_DROP_SCHEMA_FILE := $(TEST_MYSQL_DIR)/drop_fivecolors_test.sql
MYSQL_DATA_FILE := $(TEST_MYSQL_DIR)/data_fivecolors_test.sql

#Wrk parameters
WRK_CONNS ?= 100
WRK_THREADS ?= 10
WRK_DURATION ?= 10s
WRK_URL ?= http://localhost:6080/wrk.makefile@email.com

.PHONY: default
default: build

.PHONY: install
install: install_sw_deps sync_deps
	@echo "$(REPO) installed successfully" 

.PHONY: install_sw_deps
install_sw_deps:
	#Remove default brew nginx
	#brew uninstall --force nginx

	#Just unlink default brew formula nginx
	brew unlink nginx
	brew tap homebrew/nginx
	brew install nginx-full --with-auth-req
	#brew link nginx-full

	brew install memcached
	brew install cassandra
	brew install mysql
	brew install mongodb
	brew install go
	go get -u github.com/kardianos/govendor

.PHONY: install_deps
install_deps:
	govendor fetch github.com/spf13/viper
	govendor fetch github.com/uber-go/zap
	govendor fetch github.com/Sirupsen/logrus/...
	govendor fetch github.com/valyala/fasthttp
	govendor fetch github.com/valyala/quicktemplate/...
	#govendor fetch github.com/valyala/quicktemplate/qtc
	govendor fetch github.com/valyala/bytebufferpool
	govendor fetch github.com/SermoDigital/jose
	govendor fetch github.com/bradfitz/gomemcache/memcache
	govendor fetch github.com/gocql/gocql
	govendor fetch gopkg.in/mgo.v2
	govendor fetch github.com/go-sql-driver/mysql

.PHONY: sync_deps
sync_deps:
	govendor sync

.PHONY: docker
docker: build_linux
	docker build --rm -t rjansen/cassandra $(ETC_DIR)/cassandra
	docker build --rm -t rjansen/memcached $(ETC_DIR)/memcached
	docker build --rm -t rjansen/redis $(ETC_DIR)/redis
	docker build --rm -t rjansen/security $(ETC_DIR)/security

	docker create -it -p 127.0.0.1:9042:9042 -p 127.0.0.1:9160:9160 --name cassandra rjansen/cassandra
	docker create -it -p 127.0.0.1:11211:11211 --name memcached rjansen/memcached
	docker create -it -p 127.0.0.1:6379:6379 --name redis rjansen/redis
	docker create -it -p 127.0.0.1:8080:8080 --name security rjansen/security

.PHONY: build
build:
	@echo "Building $(REPO)@$(VERSION)-$(BUILD)"
	qtc 
	go build $(REPO)

.PHONY: build_linux
build_linux:
	GOARCH="amd64" GOOS="linux" go build -o $(CONF_DIR)/$(NAME) $(REPO) 

.PHONY: clean
clean: 
	-rm $(NAME)*coverage*
	-rm *.test
	-rm *.pprof

.PHONY: reset
reset: clean 
	-cd vendor; rm -r */

.PHONY: local
local: 
	@echo "Set enviroment to local"
	$(eval ENV = "local")

.PHONY: dev
dev: 
	@echo "Set enviroment to dev"
	$(eval ENV = "dev")

.PHONY: prod
prod: 
	@echo "Set enviroment to prod"
	$(eval ENV = "prod")

.PHONY: check_env
check_env:
	@if [ "$(ENV)" == "" ]; then \
	    echo "Env is blank"; \
	    exit 540; \
	fi

.PHONY: conf
conf: check_env
	@echo "Configuring Security to enviroment: $(ENV)"
	$(eval CONF = $(CONF_DIR)/$(NAME).$(ENV).$(CONF_TYPE))

.PHONY: check_conf
check_conf:
	@if [ ! -f $(CONF) ]; then \
	    echo "Did not find the config file: $(CONF)"; \
	    exit 541; \
	fi

.PHONY: run
run: build conf check_conf
	./$(NAME) -ecf $(CONF)

.PHONY: test_all
test_all:
	go test -v -race  $(PKGS)

.PHONY: test
test:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Test All Pkgs";\
		go test -v -race $(PKGS) || exit 501;\
	else \
	    echo "Test Selected Pkgs=$(TEST_PKGS)";\
		SELECTED_TEST_PKGS="";\
	    for tstpkg in $(TEST_PKGS); do \
			go test -v -race $(REPO)/$$tstpkg || exit 501;\
		done; \
	fi

.PHONY: bench
bench: up_cassandra run_cql up_mongo run_mongo up_mysql run_mysql benchmark down_cassandra down_mongo down_mysql 

.PHONY: benchmark_all
benchmark_all:
	#go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $(PKGS)
	go test -bench=. -run="^$$" -benchmem $(PKGS)

.PHONY: benchmark
benchmark:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Benchmark all Pkgs" ;\
	    for tstpkg in $(PKGS); do \
		    go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $$tstpkg || exit 501;\
		done; \
	else \
	    echo "Benchmark Selected Pkgs=$(TEST_PKGS)" ;\
	    for tstpkg in $(TEST_PKGS); do \
		    go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $(REPO)/$$tstpkg || exit 501;\
		done; \
	fi

.PHONY: coverage
coverage:
	@echo "Testing with coverage"
	@echo 'mode: set' > $(COVERAGE_FILE)
	@touch $(PKG_COVERAGE)
	@touch $(COVERAGE_FILE)
	@if [ "$(TEST_PKGS)" == "" ]; then \
		for pkg in $(PKGS); do \
			go test -v -coverprofile=$(PKG_COVERAGE) $$pkg || exit 501; \
			grep -v 'mode: set' $(PKG_COVERAGE) >> $(COVERAGE_FILE); \
		done; \
	else \
	    echo "Testing with covegare the Pkgs=$(TEST_PKGS)" ;\
	    for tstpkg in $(TEST_PKGS); do \
			go test -v -coverprofile=$(PKG_COVERAGE) $(REPO)/$$tstpkg || exit 501; \
			grep -v 'mode: set' $(PKG_COVERAGE) >> $(COVERAGE_FILE); \
		done; \
	fi
	@echo "Generating report"
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	open $(COVERAGE_HTML)

.PHONY: load
load: up_$(DB) up_test wrk down_test down_$(DB) 

.PHONY: wrk
wrk:
	wrk -c $(WRK_CONNS) -t $(WRK_THREADS) -d $(WRK_DURATION) $(WRK_URL)

.PHONY: $(NAME).pid
$(NAME).pid: build
	./$(NAME) --cfg $(TEST_CONF) & echo $$! > $(NAME).pid
	sleep 5

.PHONY: up_test
up_test: $(NAME).pid

.PHONY: down_test
#down_test: $(NAME).pid
down_test:
	@#kill `cat $<` && rm $<
	kill `cat $(NAME).pid` && rm $(NAME).pid

.PHONY: up_cassandra
up_cassandra:
	@echo "Up cassandra" 
	nohup cassandra -p cassandra.pid
	sleep 30
	@echo "Dropping cassandra schema" 
	-cqlsh -u $(DB_USER) -p $(DB_PWD) -k $(DB_CATALOG) -f $(CASSANDRA_DROP_SCHEMA_FILE)
	-cqlsh -u cassandra -p cassandra -f $(CASSANDRA_DROP_KEY_FILE)
	@echo "Creating cassandra" 
	cqlsh -u cassandra -p cassandra -f $(CASSANDRA_KEY_FILE)
	cqlsh -u $(DB_USER) -p $(DB_PWD) -k $(DB_CATALOG) -f $(CASSANDRA_SCHEMA_FILE)

.PHONY: down_cassandra
down_cassandra:
	@echo "Dropping cassandra schema" 
	-cqlsh -u $(DB_USER) -p $(DB_PWD) -k $(DB_CATALOG) -f $(CASSANDRA_DROP_SCHEMA_FILE)
	-cqlsh -u cassandra -p cassandra -f $(CASSANDRA_DROP_KEY_FILE)
	@echo "Down cassandra" 
	kill `cat cassandra.pid` && rm cassandra.pid nohup.out

.PHONY: run_cql
run_cql:
	@echo "Executing cassandra cql"
	cqlsh -u $(DB_USER) -p $(DB_PWD) -k $(DB_CATALOG) -f $(CASSANDRA_DATA_FILE)
	cqlsh -u $(DB_USER) -p $(DB_PWD) -k $(DB_CATALOG) -e "select * from login"

.PHONY: up_mongo
up_mongo:
	@echo "Up mongo" 
	mongod --config /usr/local/etc/mongod.conf & echo $$! > mongo.pid	
	sleep 30
	@echo "Dropping mongo schema" 
	-mongo $(DB_CATALOG) -u $(DB_USER) -p $(DB_PWD) $(MONGO_DROP_SCHEMA_FILE)
	-mongo admin -u admin -p mongo < $(MONGO_DROP_DB_FILE)
	@echo "Creating mongo" 
	mongo admin -u admin -p mongo < $(MONGO_DB_FILE)
	mongo $(DB_CATALOG) -u $(DB_USER) -p $(DB_PWD) $(MONGO_SCHEMA_FILE)

.PHONY: down_mongo
down_mongo:
	@echo "Dropping mongo schema" 
	-mongo $(DB_CATALOG) -u $(DB_USER) -p $(DB_PWD) $(MONGO_DROP_SCHEMA_FILE)
	mongo admin -u admin -p mongo < $(MONGO_DROP_DB_FILE)
	@echo "Down mongo" 
	kill `cat mongo.pid` && rm mongo.pid

.PHONY: run_mongo
run_mongo:
	@echo "Executing mongo script"
	mongo $(DB_CATALOG) -u $(DB_USER) -p $(DB_PWD) $(MONGO_DATA_FILE)
	mongo $(DB_CATALOG) -u $(DB_USER) -p $(DB_PWD) --eval "db.login.find()"

.PHONY: up_mysql
up_mysql:
	@echo "Up mysql" 
	mysql.server start

.PHONY: down_mysql
down_mysql:
	@echo "Down mysql" 
	mysql.server stop

.PHONY: run_mysql
run_mysql:
	@echo "Executing mysql script"
	mysql -u $(DB_USER) -p$(DB_PWD) -e "select * from login" $(DB_CATALOG)

.PHONY: test_cassandra
test_cassandra: up_cassandra run_cql down_cassandra

.PHONY: test_mongo
test_mongo: up_mongo run_mongo down_mongo

.PHONY: test_mysql
test_mysql: up_mysql run_mysql down_mysql

.PHONY: cassandra
cassandra:
	cassandra

.PHONY: mongo
mongo:
	mongod --config /usr/local/etc/mongod.conf &

.PHONY: mysql
mysql:
	mysql.server start



#TODO: Remove and use docker
NGINX_CONF_DIR := $(ETC_DIR)/nginx
NGINX_CONF := $(NGINX_CONF_DIR)/$(NAME).nginx.conf
#NGINX_PID_FILE := /usr/local/var/run/$(NAME)__$(ENV)_nginx.pid

.PHONY: filter_nginx_conf
filter_nginx_conf: check_env
	@echo "Filtering Nginx Conf Env=$(ENV)"
	@source $(NGINX_CONF_DIR)/$(NAME).nginx.$(ENV).etv && ENV=$(ENV) eval "echo \"`cat $(NGINX_CONF_DIR)/$(NAME).nginx.etf`\"" > $(NGINX_CONF)

.PHONY: check_conf
check_nginx_conf:
	@if [ ! -f $(NGINX_CONF) ]; then \
	    echo "Nginx Config file: $(NGINX_CONF) not found for Env: $(ENV)"; \
	    exit 541; \
	fi

.PHONY: stop_nginx
stop_nginx: check_env
	@if [ -f /usr/local/var/run/$(NAME)_$(ENV)_nginx.pid ]; then \
		nginx -s stop -c $(NGINX_CONF); \
	fi

.PHONY: quit_nginx
quit_nginx: check_env
	@if [ -f /usr/local/var/run/$(NAME)_$(ENV)_nginx.pid ]; then \
		nginx -s quit -c $(NGINX_CONF); \
	fi

.PHONY: nginx 
nginx: filter_nginx_conf check_nginx_conf stop_nginx
	nginx -c $(NGINX_CONF)
