package kubernetes

import (
	"fmt"

	v1 "k8s.io/api/apps/v1"
	kube "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubectl/pkg/scheme"
)

func NewKubernetesClientFrom(config *restclient.Config) (*kube.Clientset, error) {
	// create the clientset
	clientset, err := kube.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func NewClientConfigFrom(configPath string) (*restclient.Config, error) {
	// use the current context in kubeconfig
	if configPath == "" {
		return nil, fmt.Errorf("kubeconfig path not specified")
	}

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		return nil, err
	}
	if err := setConfigDefaults(config); err != nil {
		return nil, err
	}
	return config, nil
}

func setConfigDefaults(config *restclient.Config) error {
	gv := v1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()

	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	return nil
}
