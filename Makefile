BIN         := security
REPO        := farm.e-pedion.com/repo/security
BUILD       := $(shell git rev-parse --short HEAD)
#VERSION     := $(shell git describe --tags $(shell git rev-list --tags --max-count=1))
MAKEFILE    := $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))
BASE_DIR    := $(shell cd $(dir $(MAKEFILE)); pwd)
ALLSOURCES  := $(shell find . -type f -name '*.go')

ETC_DIR := $(BASE_DIR)/etc
NGNIX_ETC_DIR := $(ETC_DIR)/nginx
NGINX_CONF_DIR := /usr/local/etc/nginx
NGINX_PID_FILE := /usr/local/var/run/security_nginx.pid

ECV_DEV := $(BASE_DIR)/config.dev.ecv
ECV_PROD := $(BASE_DIR)/config.prod.ecv
ECT := $(BASE_DIR)/config.ect
ECF := $(BASE_DIR)/security.ecf

TARGET_ENV := local
TEST_PKGS := 

.PHONY: default
default: build

.PHONY: setup
setup: install_sw_deps install_deps setup_nginx
	@echo "Security set" 

.PHONY: setup_nginx
setup_nginx:
	@echo "nginx set"
	#cp $(NGNIX_ETC_DIR)/fivecolors-web.conf $(NGINX_CONF_DIR)/fivecolors-web.conf

.PHONY: install_sw_deps
install_sw_deps:
	#Remove default brew nginx
	#brew uninxtsall --force nginx

	#Only unlink default brew formula nginx
	brew unlink nginx
	brew tap homebrew/nginx
	brew install nginx-full --with-upload-module
	#brew link nginx-full

.PHONY: install_deps
install_deps:
#	go get github.com/go-sql-driver/mysql
	go get github.com/vharitonsky/iniflags
	go get github.com/op/go-logging
	go get github.com/valyala/fasthttp
	go get github.com/valyala/quicktemplate
	go get github.com/valyala/quicktemplate/qtc
	go get github.com/SermoDigital/jose
	go get github.com/bradfitz/gomemcache/memcache
	go get github.com/gocql/gocql

.PHONY: local
local: 
	@echo "Set enviroment to local"
	$(eval TARGET_ENV = "local")

.PHONY: dev
dev: 
	@echo "Set enviroment to dev"
	$(eval TARGET_ENV = "dev")

.PHONY: prod
prod: 
	@echo "Set enviroment to prod"
	$(eval TARGET_ENV = "prod")

.PHONY: build
build:
	qtc 
	go build farm.e-pedion.com/repo/security

.PHONY: run
run: build
	./security --bind_address=:8000

.PHONY: pkg_data
pkg_data:
	@echo "Add data pkg for tests"
	$(eval TEST_PKGS += "farm.e-pedion.com/repo/fivecolors/data")

.PHONY: pkg_api
pkg_api:
	@echo "Add api pkg for tests"
	$(eval TEST_PKGS += "farm.e-pedion.com/repo/fivecolors/api")

.PHONY: pkg_test
pkg_test: pkg_data pkg_api
	@echo "TEST_PKGS=$(TEST_PKGS)"

.PHONY: test
test:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Build Without TEST_PKGS" ;\
	    go test farm.e-pedion.com/repo/fivecolors/data farm.e-pedion.com/repo/fivecolors/api ;\
	else \
	    echo "Build With TEST_PKGS=$(TEST_PKGS)" ;\
	    go test $(TEST_PKGS) ;\
	fi

.PHONY: stop_nginx
stop_nginx:
	@if [ -f $(NGINX_PID_FILE) ]; then \
		nginx -s stop -c $(NGNIX_ETC_DIR)/security.nginx.conf; \
	fi

.PHONY: quit_nginx
quit_nginx:
	@if [ -f $(NGINX_PID_FILE) ]; then \
		nginx -s quit -c $(NGNIX_ETC_DIR)/security.nginx.conf; \
	fi

.PHONY: nginx 
nginx: stop_nginx
	nginx -c $(NGNIX_ETC_DIR)/security.nginx.conf
