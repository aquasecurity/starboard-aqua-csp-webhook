package etc

import (
	"os"

	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
)

type Config struct {
	API       API
	Starboard Starboard
}

type API struct {
	Addr string `env:"STARBOARD_WEBHOOK_API_ADDR" envDefault:":4000"`
}

type Starboard struct {
	Namespace string `env:"STARBOARD_WEBHOOK_STARBOARD_NAMESPACE" envDefault:"starboard"`
}

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
	return
}

func GetLogLevel() logrus.Level {
	if value, ok := os.LookupEnv("STARBOARD_WEBHOOK_LOG_LEVEL"); ok {
		level, err := logrus.ParseLevel(value)
		if err != nil {
			return logrus.InfoLevel
		}
		return level
	}
	return logrus.InfoLevel
}
