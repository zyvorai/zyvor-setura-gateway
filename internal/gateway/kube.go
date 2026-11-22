package gateway

import (
	"errors"
	"flag"
	"io"
)

type kubeFlags struct{}

func addKubeFlags(fs *flag.FlagSet) *kubeFlags { return &kubeFlags{} }

func (k *kubeFlags) source(io.Writer) (Source, error) { return nil, errors.New("not implemented") }
