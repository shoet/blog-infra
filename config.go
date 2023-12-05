package main

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
)

type Config struct {
	BastionSSHKeyName      string `env:"BASTION_SSH_KEY_NAME"`
	KmsKeyId               string `env:"KMS_KEY_ID"`
	SecretsManagerSecretId string `env:"SECRETS_MANAGER_SECRET_ID"`
	SSLCertificateArn      string `env:"SSL_CERTIFICATE_ARN"`
	CorsWhiteList          string `env:"CORS_WHITE_LIST"`
}

func NewConfig() (*Config, error) {
	if err := loadEnv(); err != nil {
		return nil, fmt.Errorf("error loading .env file: %w", err)
	}
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}
	return cfg, nil
}

func loadEnv() error {
	err := godotenv.Load()
	if err != nil {
		return fmt.Errorf("error loading .env file: %w", err)
	}
	return nil
}

func (c *Config) GetCORSWhiteList() []string {
	whiteList := strings.Split(c.CorsWhiteList, ",")
	return whiteList
}
