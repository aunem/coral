package config

import (
	"github.com/spf13/viper"
)

// ServerConfig represents the general config for the server
type ServerConfig struct {
	TokenTTL     int64
	Issuer       string
	RootName     string
	RootPass     string
	Debug        bool
	WriteDB      *DB
	ReadDB       *DB
	AuditWriteDB *DB
	AuditReadDB  *DB
	ColdDB       *DB
}

// DB represents a database connection
type DB struct {
	Type string
	Host string
	User string
	Pass string
	Port string
	DB   string
}

// GetConfig gets the current configuration of the server
func GetConfig() *ServerConfig {
	viper.SetDefault("token_ttl", 86400)
	viper.SetDefault("issuer", "localhost")
	viper.SetDefault("root_name", "root")
	viper.SetDefault("root_pass", "pass")
	viper.SetDefault("debug", true) //TODO: default to false before prod

	viper.AutomaticEnv()

	return &ServerConfig{
		TokenTTL: viper.GetInt64("token_ttl"),
		Issuer:   viper.GetString("issuer"),
		RootName: viper.GetString("root_name"),
		RootPass: viper.GetString("root_pass"),
		Debug:    viper.GetBool("debug"),
	}
}
