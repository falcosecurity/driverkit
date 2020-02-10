package kubernetes

import (
	"fmt"

	kube "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func NewKubernetesClientFromConfigPath(configPath string) (*kube.Clientset, error) {
	// use the current context in kubeconfig
	if configPath == "" {
		return nil, fmt.Errorf("kubeconfig path not specified")
	}

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		return nil, err
	}

	// create the clientset
	clientset, err := kube.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

