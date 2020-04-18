package etc

import (
	"github.com/caarlos0/env/v6"
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
