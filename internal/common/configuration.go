package common

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

const (
	DatabaseTypeMocked = "mocked"
	DatabaseTypeMySQL  = "mysql"
	DatabaseTypeSQLite = "sqlite"
)

type Configuration struct {
	Core struct {
		ListenAddress       string `yaml:"listen_address" envconfig:"CORE_LISTEN_ADDRESS"`
		Port                int    `yaml:"port" envconfig:"CORE_PORT"`
		DisableRegistration bool   `yaml:"disable_registration" envconfig:"CORE_DISABLE_REGISTRATION"`
		VaultURL            string `yaml:"vault_url" envconfig:"CORE_VAULT_URL"`
	} `yaml:"core"`
	Database struct {
		Type     string `yaml:"type" envconfig:"DATABASE_TYPE"`         // either 'sqlite' or 'mysql'
		Location string `yaml:"location" envconfig:"DATABASE_LOCATION"` // sqlite
		Host     string `yaml:"host" envconfig:"DATABASE_HOST"`         // mysql
		Port     int    `yaml:"port" envconfig:"DATABASE_PORT"`
		VHost    string `yaml:"vhost" envconfig:"DATABASE_NAME"`
		Username string `yaml:"user" envconfig:"DATABASE_USERNAME"`
		Password string `yaml:"pass" envconfig:"DATABASE_PASSWORD"`
	} `yaml:"database"`
	Security struct {
		SigningKey string `yaml:"signing_key" envconfig:"SECURITY_SIGNING_KEY"`
		JWTExpire  int    `yaml:"jwt_expire" envconfig:"SECURITY_JWT_EXPIRE"`
	} `yaml:"security"`
	Email struct {
		Host        string `yaml:"host" envconfig:"EMAIL_HOST"`
		Port        int    `yaml:"port" envconfig:"EMAIL_PORT"`
		TLS         bool   `yaml:"tls" envconfig:"EMAIL_TLS"`
		Username    string `yaml:"user" envconfig:"EMAIL_USERNAME"`
		Password    string `yaml:"pass" envconfig:"EMAIL_PASSWORD"`
		FromAddress string `yaml:"from" envconfig:"EMAIL_FROM"`
		FromName    string `yaml:"name" envconfig:"EMAIL_NAME"`
	} `yaml:"email"`
}

func setDefaultValues(cfg *Configuration) {
	cfg.Core.ListenAddress = ""          // Listen on all interfaces
	cfg.Core.Port = 8080                 // Listen on port 8080
	cfg.Core.DisableRegistration = false // Allow registration
	cfg.Core.VaultURL = ""               // Empty vault URL

	cfg.Database.Type = DatabaseTypeSQLite // Use SQLite database
	cfg.Database.Location = ""             // Store database in same directory as the executable

	cfg.Security.SigningKey = "secret" // Signing key
	cfg.Security.JWTExpire = 3600      // Amount of time (in seconds) the generated JSON Web Tokens will last before expiry.
}

func readConfigFile(cfg *Configuration, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		return err
	}

	return nil
}

func readConfigEnv(cfg *Configuration) error {
	err := envconfig.Process("", cfg)
	if err != nil {
		return err
	}

	return nil
}

// LoadConfiguration loads a configuration file from a custom location and parses environment variables
func LoadConfiguration(filename string) (*Configuration, error) {
	var cfg Configuration

	setDefaultValues(&cfg)

	if filename != "" {
		err := readConfigFile(&cfg, filename)
		if err != nil {
			log.Error("Configuration reading failed: ", err)
			dir, _ := os.Getwd()
			log.Debug("Working directory: ", dir)

			return nil, err
		}
	}

	err := readConfigEnv(&cfg)
	if err != nil {
		log.Error("Configuration env parsing failed: ", err)
		return nil, err
	}

	return &cfg, nil
}
