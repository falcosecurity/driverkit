package cmd

var kubernetesOptions = &KubeOptions{}

type KubeOptions struct {
	RunAsUser       int64  `json:"runAsUser,omitempty" protobuf:"varint,2,opt,name=runAsUser" default:"0"`
	Namespace       string `validate:"required" name:"namespace" default:"default"`
	ImagePullSecret string `validate:"omitempty" name:"image-pull-secret" default:""`
}
