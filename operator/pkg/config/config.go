package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config represents the structure of the configuration
type Config struct {
	Paladin struct {
		Image       string            `json:"image"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Envs        map[string]string `json:"envs"`
		// TODO: Add more fields
	} `json:"paladin"`
}

// LoadConfig sets up Viper to load the config file
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("json")

	configPath := "config/"
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		configPath = p
	}
	viper.AddConfigPath(configPath)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err := viper.Unmarshal(&config) // Unmarshal into the Config struct
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
