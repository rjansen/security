NAME 		:= security
BIN         := $(NAME)
REPO        := farm.e-pedion.com/repo/$(NAME)
BUILD       := $(shell git rev-parse --short HEAD)
#VERSION     := $(shell git describe --tags $(shell git rev-list --tags --max-count=1))
MAKEFILE    := $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))
BASE_DIR    := $(shell cd $(dir $(MAKEFILE)); pwd)
PKGS        := $(shell go list ./... | grep -v /vendor/)
COVERAGE_FILE   := $(NAME).coverage
COVERAGE_HTML  	:= $(NAME).coverage.html
PKG_COVERAGE   	:= $(NAME).pkg.coverage


ETC_DIR := ./etc
CONF_DIR := $(ETC_DIR)/$(NAME)
CONF_TYPE := yaml
CONF := $(CONF_DIR)/$(NAME).$(CONF_TYPE)

#CONF := $(CONF_DIR)/$(NAME).conf
#PID_FILE := /usr/local/var/run/$(NAME)_$(ENV).pid

NGINX_CONF_DIR := $(ETC_DIR)/nginx
NGINX_CONF := $(NGINX_CONF_DIR)/$(NAME).nginx.conf
#NGINX_PID_FILE := /usr/local/var/run/$(NAME)__$(ENV)_nginx.pid

TEST_ETC_DIR := ./test/etc
TEST_CONF_DIR := $(TEST_ETC_DIR)/$(NAME)
TEST_CONF_TYPE := yaml
TEST_CONF := $(TEST_CONF_DIR)/$(NAME).$(TEST_CONF_TYPE)

CASSANDRA_USER := fivecolors_test
CASSANDRA_PWD := fivecolors_test
CASSANDRA_KEY := fivecolors_test
TEST_CQL_DIR := $(TEST_ETC_DIR)/cassandra/script
CASSANDRA_KEY_FILE := $(TEST_CQL_DIR)/keyspace.cql
CASSANDRA_DROP_KEY_FILE := $(TEST_CQL_DIR)/drop_keyspace.cql
CASSANDRA_SCHEMA_FILE := $(TEST_CQL_DIR)/fivecolors_test.cql
CASSANDRA_DROP_SCHEMA_FILE := $(TEST_CQL_DIR)/drop_fivecolors_test.cql
CASSANDRA_DATA_FILE := $(TEST_CQL_DIR)/data_fivecolors_test.cql

MONGO_USER := fivecolors_test
MONGO_PWD := fivecolors_test
MONGO_DB := fivecolors_test
TEST_MONGO_DIR := $(TEST_ETC_DIR)/mongo/script
MONGO_DB_FILE := $(TEST_MONGO_DIR)/database.mongo
MONGO_DROP_DB_FILE := $(TEST_MONGO_DIR)/drop_database.mongo
MONGO_SCHEMA_FILE := $(TEST_MONGO_DIR)/fivecolors_test.js
MONGO_DROP_SCHEMA_FILE := $(TEST_MONGO_DIR)/drop_fivecolors_test.js
MONGO_DATA_FILE := $(TEST_MONGO_DIR)/data_fivecolors_test.js

WRK_CONNS ?= 100
WRK_THREADS ?= 10
WRK_DURATION ?= 10s
WRK_URL ?= http://localhost:6080/wrk.makefile@email.com

ENV ?= local
TEST_PKGS ?= 

.PHONY: default
default: build

.PHONY: setup
setup: install_sw_deps install_deps setup_nginx
	@echo "Security set" 

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
	brew install go

.PHONY: install_deps
install_deps:
	go get -u github.com/kardianos/govendor
#	go get github.com/go-sql-driver/mysql
	go get github.com/vharitonsky/iniflags
	go get github.com/op/go-logging
	go get github.com/valyala/fasthttp
	go get github.com/valyala/quicktemplate
	go get github.com/valyala/quicktemplate/qtc
	go get github.com/valyala/bytebufferpool
	go get github.com/SermoDigital/jose
	go get github.com/bradfitz/gomemcache/memcache
	go get github.com/gocql/gocql

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
	    echo "Env is blank: $(ENV)"; \
	    exit 540; \
	fi

.PHONY: filter_conf
filter_conf: check_env
	@echo "Filtering Conf Env=$(ENV)"
	@source $(CONF_DIR)/$(NAME).$(ENV).etv && eval "echo \"`cat $(CONF_DIR)/$(NAME).etf`\"" > $(CONF)

.PHONY: check_conf
check_conf:
	@if [ ! -f $(CONF) ]; then \
	    echo "Config file: $(CONF) not found for Env: $(ENV)"; \
	    exit 541; \
	fi

.PHONY: build
build:
	qtc 
	go build $(REPO)

.PHONY: build_linux
build_linux:
	GOARCH="amd64" GOOS="linux" go build -o $(CONF_DIR)/$(NAME) farm.e-pedion.com/repo/security 

.PHONY: run
#run: filter_conf check_conf build
run: build
	./$(NAME) --cfg $(CONF)

.PHONY: test_loop
test_loop:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Test All Pkgs";\
	    for pkg in $(PKGS); do \
			go test -v -race $$pkg || exit 501;\
		done; \
	else \
	    echo "Test Selected Pkgs=$(TEST_PKGS)";\
	    for tstpkg in $(TEST_PKGS); do \
		    go test -v -race $(REPO)/$$tstpkg || exit 501;\
		done; \
	fi

.PHONY: test_all
test_all:
	go test -v -race 

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

.PHONY: bench_all
bench_all:
	#go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $(PKGS)
	go test -bench=. -run="^$$" -benchmem $(PKGS)

.PHONY: bench
bench:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Bench All Pkgs" ;\
	    for tstpkg in $(PKGS); do \
		    go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $$tstpkg || exit 501;\
		done; \
	else \
	    echo "Test Selected Pkgs=$(TEST_PKGS)" ;\
	    for tstpkg in $(TEST_PKGS); do \
		    go test -bench=. -run="^$$" -cpuprofile=cpu.pprof -memprofile=mem.pprof -benchmem $(REPO)/$$tstpkg || exit 501;\
		done; \
	fi

.PHONY: coverage
coverage:
	@echo "Running tests with coverage report..."
	@echo 'mode: set' > $(COVERAGE_FILE)
	@touch $(PKG_COVERAGE)
	@touch $(COVERAGE_FILE)
	@if [ "$(TEST_PKGS)" == "" ]; then \
		for pkg in $(PKGS); do \
			go test -v -coverprofile=$(PKG_COVERAGE) $$pkg || exit 501; \
			grep -v 'mode: set' $(PKG_COVERAGE) >> $(COVERAGE_FILE); \
		done; \
	else \
	    echo "Covegare Test Selected Pkgs=$(TEST_PKGS)" ;\
	    for tstpkg in $(TEST_PKGS); do \
			go test -v -coverprofile=$(PKG_COVERAGE) $(REPO)/$$tstpkg || exit 501; \
			grep -v 'mode: set' $(PKG_COVERAGE) >> $(COVERAGE_FILE); \
		done; \
	fi
	@echo "Generating HTML report in $(COVERAGE_HTML)..."
	go tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@(which -s open && open $(COVERAGE_HTML)) || (which -s gnome-open && gnome-open $(COVERAGE_HTML)) || (exit 0)

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

.PHONY: create_cassandra
create_cassandra:
	@echo "Creating cassandra" 
	cqlsh -u cassandra -p cassandra -f $(CASSANDRA_KEY_FILE)
	cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_SCHEMA_FILE)

.PHONY: run_cql
run_cql:
	@echo "Executing cql"
	cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_DATA_FILE)
	cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -e "select * from login"

.PHONY: drop_cassandra
drop_cassandra:
	@echo "Dropping cassandra schema" 
	cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_DROP_SCHEMA_FILE)
	cqlsh -u cassandra -p cassandra -f $(CASSANDRA_DROP_KEY_FILE)

.PHONY: down_cassandra
down_cassandra:
	@echo "Down cassandra" 
	@echo "Dropping cassandra schema" 
	-cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_DROP_SCHEMA_FILE)
	cqlsh -u cassandra -p cassandra -f $(CASSANDRA_DROP_KEY_FILE)

.PHONY: up_cassandra
up_cassandra:
	@echo "Up cassandra" 
	@echo "Dropping cassandra schema" 
	-cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_DROP_SCHEMA_FILE)
	-cqlsh -u cassandra -p cassandra -f $(CASSANDRA_DROP_KEY_FILE)
	@echo "Creating cassandra" 
	cqlsh -u cassandra -p cassandra -f $(CASSANDRA_KEY_FILE)
	cqlsh -u $(CASSANDRA_USER) -p $(CASSANDRA_PWD) -k $(CASSANDRA_KEY) -f $(CASSANDRA_SCHEMA_FILE)

.PHONY: run_mongo
run_mongo:
	@echo "Executing mongo"
	mongo $(MONGO_DB) -u $(MONGO_USER) -p $(MONGO_PWD) $(MONGO_DATA_FILE)
	mongo $(MONGO_DB) -u $(MONGO_USER) -p $(MONGO_PWD) --eval "db.login.find()"

.PHONY: down_mongo
down_mongo:
	@echo "Down mongo" 
	@echo "Dropping mongo schema" 
	-mongo $(MONGO_DB) -u $(MONGO_USER) -p $(MONGO_PWD) $(MONGO_DROP_SCHEMA_FILE)
	mongo admin -u admin -p mongo < $(MONGO_DROP_DB_FILE)

.PHONY: up_mongo
up_mongo:
	@echo "Up mongo" 
	@echo "Dropping mongo schema" 
	-mongo $(MONGO_DB) -u $(MONGO_USER) -p $(MONGO_PWD) $(MONGO_DROP_SCHEMA_FILE)
	-mongo admin -u admin -p mongo < $(MONGO_DROP_DB_FILE)
	@echo "Creating mongo" 
	mongo admin -u admin -p mongo < $(MONGO_DB_FILE)
	mongo $(MONGO_DB) -u $(MONGO_USER) -p $(MONGO_PWD) $(MONGO_SCHEMA_FILE)

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

.PHONY: wrk
wrk:
	wrk -c $(WRK_CONNS) -t $(WRK_THREADS) -d $(WRK_DURATION) $(WRK_URL)

.PHONY: load_test
load_test: up_cassandra up_test wrk down_test down_cassandra 

.PHONY: bench_test
bench_test: up_cassandra run_cql up_mongo run_mongo bench down_cassandra down_mongo 

.PHONY: test_cassandra
test_cassandra: up_cassandra run_cql down_cassandra

.PHONY: test_cassandra
test_mongo: up_mongo run_mongo down_mongo

.PHONY: cassandra
cassandra:
	cassandra
