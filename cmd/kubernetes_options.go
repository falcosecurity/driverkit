package cmd

import flag "github.com/spf13/pflag"

var kubernetesOptions = &KubeOptions{}

type KubeOptions struct {
	RunAsUser       int64  `json:"runAsUser,omitempty" protobuf:"varint,2,opt,name=runAsUser" default:"0"`
	Namespace       string `validate:"required" name:"namespace" default:"default"`
	ImagePullSecret string `validate:"omitempty" name:"image-pull-secret" default:""`
}

func addKubernetesFlags(flags *flag.FlagSet) {
	flags.StringVarP(&kubernetesOptions.Namespace, "namespace", "n", "default", "If present, the namespace scope for the pods and its config ")
	flags.Int64Var(&kubernetesOptions.RunAsUser, "run-as-user", 0, "Pods runner user")
	flags.StringVar(&kubernetesOptions.ImagePullSecret, "image-pull-secret", "", "ImagePullSecret")
}
