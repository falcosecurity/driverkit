package driverbuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	logger "github.com/sirupsen/logrus"

	buildmeta "github.com/falcosecurity/driverkit/pkg/driverbuilder/build"
	"github.com/falcosecurity/driverkit/pkg/driverbuilder/builder"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/exec"
	"k8s.io/utils/pointer"
)

const KubernetesBuildProcessorName = "kubernetes"

var builderBaseImage = "falcosecurity/driverkit-builder-base:latest" // This is overwritten when using the Makefile to build
const falcoBuilderUIDLabel = "org.falcosecurity/driverkit-uid"

type KubernetesBuildProcessor struct {
	coreV1Client v1.CoreV1Interface
	clientConfig *restclient.Config
	namespace    string
	timeout      int
}

// NewKubernetesBuildProcessor constructs a KubernetesBuildProcessor
// starting from a kubernetes.Clientset. bufferSize represents the length of the
// channel we use to do the builds. A bigger bufferSize will mean that we can save more Builds
// for processing, however setting this to a big value will have impacts
func NewKubernetesBuildProcessor(corev1Client v1.CoreV1Interface, clientConfig *restclient.Config, namespace string, timeout int) *KubernetesBuildProcessor {
	return &KubernetesBuildProcessor{
		coreV1Client: corev1Client,
		clientConfig: clientConfig,
		namespace:    namespace,
		timeout:      timeout,
	}
}

func (bp *KubernetesBuildProcessor) String() string {
	return KubernetesBuildProcessorName
}

func (bp *KubernetesBuildProcessor) Start(b *buildmeta.Build) error {
	logger.Debug("doing a new kubernetes build")
	return bp.buildModule(b)
}

func (bp *KubernetesBuildProcessor) buildModule(build *buildmeta.Build) error {
	deadline := int64(bp.timeout)
	namespace := bp.namespace
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))

	podClient := bp.coreV1Client.Pods(namespace)
	configClient := bp.coreV1Client.ConfigMaps(namespace)

	// create a builder based on the choosen build type
	v, err := builder.Factory(build.BuildType)
	if err != nil {
		return err
	}

	bc := builder.BuilderConfig{
		ModuleConfig: builder.ModuleConfig{
			ModuleName:      "falco",                                    // TODO: make this configurable
			DeviceName:      "falco",                                    // TODO: make this configurable
			DownloadBaseURL: "https://github.com/draios/sysdig/archive", // TODO: make this configurable
		},
		Build: build,
	}

	// generate the build script from the builder
	res, err := v.Script(bc)
	if err != nil {
		return err
	}

	// Append a script to the entrypoint to wait
	// for the module to be ready before exiting PID 1
	res = fmt.Sprintf("%s\n%s", res, waitForModuleScript)

	buildCmd := []string{
		"/bin/bash",
		"/module-builder/module-builder.sh",
	}

	commonMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			falcoBuilderUIDLabel: string(uid),
		},
	}

	// Prepare driver config template
	bufDriverConfig := bytes.NewBuffer(nil)
	err = renderDriverConfig(bufDriverConfig, driverConfigData{ModuleVersion: bc.Build.ModuleVersion, ModuleName: bc.ModuleConfig.ModuleName, DeviceName: bc.ModuleConfig.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: bc.ModuleConfig.ModuleName, ModuleBuildDir: builder.ModuleDirectory})
	if err != nil {
		return err
	}

	configDecoded, err := base64.StdEncoding.DecodeString(build.KernelConfigData)
	if err != nil {
		return err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: commonMeta,
		Data: map[string]string{
			"module-builder.sh":      res,
			"kernel.config":          string(configDecoded),
			"module-Makefile":        bufMakefile.String(),
			"module-driver-config.h": bufDriverConfig.String(),
			"module-downloader.sh":   waitForModuleAndCat,
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: commonMeta,
		Spec: corev1.PodSpec{
			ActiveDeadlineSeconds: pointer.Int64Ptr(deadline),
			RestartPolicy:         corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:            name,
					Image:           builderBaseImage,
					Command:         buildCmd,
					ImagePullPolicy: corev1.PullIfNotPresent,

					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("1000m"),
							corev1.ResourceMemory: resource.MustParse("2000Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("4"),
							corev1.ResourceMemory: resource.MustParse("4G"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "module-builder",
							MountPath: "/module-builder",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "module-builder",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: cm.Name,
							},
						},
					},
				},
			},
		},
	}

	_, err = configClient.Create(cm)
	if err != nil {
		return err
	}
	_, err = podClient.Create(pod)
	if err != nil {
		return err
	}

	out, err := os.Create(build.ModuleFilePath)

	if err != nil {
		return err
	}
	defer out.Close()

	return bp.copyModuleFromPodWithUID(out, namespace, string(uid))
}

func (bp *KubernetesBuildProcessor) copyModuleFromPodWithUID(out io.Writer, namespace string, falcoBuilderUID string) error {
	namespacedClient := bp.coreV1Client.Pods(namespace)
	watch, err := namespacedClient.Watch(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", falcoBuilderUIDLabel, falcoBuilderUID),
	})
	if err != nil {
		return err
	}
	// Give it ten minutes to complete, if it doesn't give an error
	// TODO(fntlnz): maybe pass this from the outside?
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return errors.New("module copy from pod interrupted before the copy was complete")
		default:
			event := <-watch.ResultChan()
			p, ok := event.Object.(*corev1.Pod)
			if !ok {
				logger.Error("unexpected type when watching pods")
				continue
			}
			if p.Status.Phase == corev1.PodPending {
				continue
			}
			if p.Status.Phase == corev1.PodRunning {
				logger.WithField(falcoBuilderUIDLabel, falcoBuilderUID).Info("start downloading module from pod")
				err = copySingleFileFromPod(out, bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name)
				if err != nil {
					return err
				}
				logger.WithField(falcoBuilderUIDLabel, falcoBuilderUID).Info("completed downloading module from pod")
			}
			return nil
		}

	}
}

func copySingleFileFromPod(out io.Writer, podClient v1.PodsGetter, clientConfig *restclient.Config, namespace, podName string) error {
	if len(namespace) == 0 {
		return errors.New("need a namespace to copy from pod")
	}

	if len(podName) == 0 {
		return errors.New("need a podName to copy from pod")
	}

	options := &exec.ExecOptions{
		PodClient: podClient,
		Config:    clientConfig,
		StreamOptions: exec.StreamOptions{
			IOStreams: genericclioptions.IOStreams{
				Out:    out,
				ErrOut: bytes.NewBuffer([]byte{}), //TODO(fntlnz): necessary to deal with errors here?
			},
			Stdin: false,

			Namespace: namespace,
			PodName:   podName,
		},

		Command: []string{
			"/bin/bash",
			"/module-builder/module-downloader.sh",
		},
		Executor: &exec.DefaultRemoteExecutor{},
	}

	if err := options.Validate(); err != nil {
		return err
	}
	if err := options.Run(); err != nil {
		return err
	}

	return nil
}
