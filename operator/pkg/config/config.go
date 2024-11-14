package config

import (
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"

	"github.com/spf13/viper"
)

type Template struct {
	Image           string                  `json:"image"`
	ImagePullPolicy corev1.PullPolicy       `json:"imagePullPolicy"`
	Labels          map[string]string       `json:"labels"`
	Annotations     map[string]string       `json:"annotations"`
	Envs            map[string]string       `json:"envs"`
	Tolerations     []corev1.Toleration     `json:"tolerations"`
	Affinity        *corev1.Affinity        `json:"affinity"`
	NodeSelector    map[string]string       `json:"nodeSelector"`
	SecurityContext *corev1.SecurityContext `json:"securityContext"`
}

// Config represents the structure of the configuration
type Config struct {
	Paladin  Template `json:"paladin"`
	Besu     Template `json:"besu"`
	Postgres Template `json:"postgres"`
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
