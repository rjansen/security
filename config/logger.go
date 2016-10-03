package config

import (
	"farm.e-pedion.com/repo/logger"
	//"flag"
	"fmt"
	"github.com/spf13/viper"
)

var (
	loggerConfig *logger.Configuration
)

//GetLoggerConfiguration gets and binds, only if necessary, parameters for the application logger
/*
Format:

%{id}        Sequence number for log message (uint64).
%{pid}       Process id (int)
%{time}      Time when log occurred (time.Time)
%{level}     Log level (Level)
%{module}    Module (string)
%{program}   Basename of os.Args[0] (string)
%{message}   Message (string)
%{longfile}  Full file name and line number: /a/b/c/d.go:23
%{shortfile} Final file name element and line number: d.go:23
%{callpath}  Callpath like main.a.b.c...c  "..." meaning recursive call ~. meaning truncated path
%{color}     ANSI color based on log level

Experimental:

%{longpkg}   Full package path, eg. github.com/go-logging
%{shortpkg}  Base package path, eg. go-logging
%{longfunc}  Full function name, eg. littleEndian.PutUint32
%{shortfunc} Base function name, eg. PutUint32
%{callpath}  Call function path, eg. main.a.b.c

*/
func GetLoggerConfiguration() *logger.Configuration {
	if loggerConfig == nil {
		loggerConfig = &logger.Configuration{}
		if err := viper.Sub("logger").Unmarshal(loggerConfig); err != nil {
			panic(err)
		}
		fmt.Printf("GetLoggerConfig=%v\n", loggerConfig)
		//flag.StringVar(&loggerConfig.Provider, "logger_provider", logger.ZAP, "Logger provider")
		//flag.IntVar(&loggerConfig.Level, "logger_level", logger.DEBUG, "Logger level")
		//flag.StringVar(&loggerConfig.Format, "logger_format", logger.TEXT, "Logger output format")
		//flag.StringVar(&loggerConfig.Out, "logger_out", logger.STDOUT, "Logger output")
	}
	return loggerConfig
}
