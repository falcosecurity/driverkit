package cmd

import (
      "fmt"

      "github.com/creasty/defaults"
      "github.com/falcosecurity/driverkit/validate"
      "github.com/go-playground/validator/v10"
      logger "github.com/sirupsen/logrus"
)

var dockerOptions *DockerOptions

// DockerOptions represent the configuration flags for the driverkit docker subcommand.
type DockerOptions struct {
      DNS          []string `validate:"gte=0,dive,ip" name:"docker dns" default:[]string{}`
      NetworkMode  string   `validate:"omitempty" name:"docker network"`

      configErrors bool
}

// NewDockerOptions creates an instance of DockerOptions.
func NewDockerOptions() *DockerOptions {
      o := &DockerOptions{}
      if err := defaults.Set(o); err != nil {
            logger.WithError(err).WithField("options", "DockerOptions").Fatal("error setting driverkit docker option defaults")
      }
      return o
}

// Validate validates the DockerOptions fields.
func (do *DockerOptions) Validate() []error {
      if err := validate.V.Struct(do); err != nil {
            errors := err.(validator.ValidationErrors)
            errArr := []error{}
            for _, e := range errors {
                  // Translate each error one at a time
                  errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
            }
            do.configErrors = true
            return errArr
      }
      return nil
}
