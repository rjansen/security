BIN         := security
REPO        := farm.e-pedion.com/repo/security
BUILD       := $(shell git rev-parse --short HEAD)
VERSION     := $(shell git describe --tags $(shell git rev-list --tags --max-count=1))
MAKEFILE    := $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))
BASE_DIR    := $(shell cd $(dir $(MAKEFILE)); pwd)
ALLSOURCES  := $(shell find . -type f -name '*.go')

ECV_DEV := $(BASE_DIR)/config.dev.ecv
ECV_PROD := $(BASE_DIR)/config.prod.ecv
ECT := $(BASE_DIR)/config.ect
ECF := $(BASE_DIR)/security.ecf

TARGET_ENV := 
TEST_PKGS := 

install:
	go build farm.e-pedion.com/repo/security

pkg_data:
	@echo "Add data pkg for tests"
	$(eval TEST_PKGS += "farm.e-pedion.com/repo/fivecolors/data")

pkg_api:
	@echo "Add api pkg for tests"
	$(eval TEST_PKGS += "farm.e-pedion.com/repo/fivecolors/api")

pkg_test: pkg_data pkg_api
	@echo "TEST_PKGS=$(TEST_PKGS)"

test:
	@if [ "$(TEST_PKGS)" == "" ]; then \
	    echo "Build Without TEST_PKGS" ;\
	    go test farm.e-pedion.com/repo/fivecolors/data farm.e-pedion.com/repo/fivecolors/api ;\
	else \
	    echo "Build With TEST_PKGS=$(TEST_PKGS)" ;\
	    go test $(TEST_PKGS) ;\
	fi

.PHONY: local
local: 
	@echo "Set enviroment to local"
	$(eval TARGET_ENV = "local")
    

.PHONY: run
run: install
	./security