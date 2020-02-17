package modulebuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/kubectl/pkg/cmd/exec"
)

const KubernetesBuildProcessorName = "kubernetes"

var builderBaseImage = "falcosecurity/falco-builder-service-base:latest" // This is overwritten when using the Makefile to build
const falcoBuilderUIDLabel = "org.falcosecurity/falco-builder-uid"

type KubernetesBuildProcessor struct {
	buildsch     chan Build
	ctx          context.Context
	logger       *zap.Logger
	coreV1Client v1.CoreV1Interface
	clientConfig *restclient.Config
	bufferSize   int
}

// NewKubernetesBuildProcessor constructs a KubernetesBuildProcessor
// starting from a kubernetes.Clientset. bufferSize represents the length of the
// channel we use to do the builds. A bigger bufferSize will mean that we can save more Builds
// for processing, however setting this to a big value will have impacts
func NewKubernetesBuildProcessor(corev1Client v1.CoreV1Interface, clientConfig *restclient.Config, bufferSize int) *KubernetesBuildProcessor {
	buildsch := make(chan Build, bufferSize)
	return &KubernetesBuildProcessor{
		buildsch:     buildsch,
		ctx:          context.TODO(),
		logger:       zap.NewNop(),
		coreV1Client: corev1Client,
		clientConfig: clientConfig,
		bufferSize:   bufferSize,
	}
}

func (bp *KubernetesBuildProcessor) String() string {
	return KubernetesBuildProcessorName
}

func (bp *KubernetesBuildProcessor) WithContext(c context.Context) {
	bp.ctx = c
}

func (bp *KubernetesBuildProcessor) WithLogger(logger *zap.Logger) {
	bp.logger = logger
	bp.logger.With(zap.String("processor", bp.String()))
}

func (bp *KubernetesBuildProcessor) Request(b Build) error {
	if len(bp.buildsch) >= bp.bufferSize {
		return fmt.Errorf("too many queued elements right now, retry later")
	}
	bp.buildsch <- b
	return nil // TODO(fntlnz): do validation and error in case
}

func (bp *KubernetesBuildProcessor) Start() error {
	for b := range bp.buildsch {
		buildlogger := bp.logger.With(
			zap.String("Architecture", b.Architecture),
			zap.String("BuildType", string(b.BuildType)),
			zap.String("KernelVersion", b.KernelVersion),
			zap.String("ModuleVersion", b.ModuleVersion),
			zap.String("SHA256", b.SHA256()),
		)
		select {
		case <-bp.ctx.Done():
			bp.logger.Info("graceful stop of the kubernetes build processor")
			return nil
		default:
			buildlogger.Info("doing a new build")
			err := bp.buildModule(b)
			if err != nil {
				buildlogger.Error("build errored", zap.Error(err))
			}
		}
	}
	return nil
}

func int64Ptr(i int64) *int64 { return &i }

func (bp *KubernetesBuildProcessor) buildModule(build Build) error {
	// TODO(fntlnz): make these configurable
	deadline := int64(1000)
	deadlineGracePeriod := int64(20)

	// TODO(fntlnz): make namespace configurable
	namespace := "default"
	name := "falco-builder" // TODO(fntlnz): generate this
	uid := "generate-a-uid" //todo(fntlnz): generate an uid here

	podClient := bp.coreV1Client.Pods(namespace)
	configClient := bp.coreV1Client.ConfigMaps(namespace)

	// create a builder based on the choosen build type
	v, err := builder.Factory(build.BuildType)
	if err != nil {
		return err
	}

	bc := builder.BuilderConfig{
		ModuleConfig: builder.ModuleConfig{
			ModuleVersion:   build.ModuleVersion,
			ModuleName:      "falco",                                    // TODO: make this configurable at startup
			DeviceName:      "falco",                                    // TODO: make this configurable at startup
			DownloadBaseURL: "https://github.com/draios/sysdig/archive", // TODO: make this configurable at startup
		},
		KernelVersion: build.KernelVersion,
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
			falcoBuilderUIDLabel: uid,
		},
	}

	// Prepare driver config template
	bufDriverConfig := bytes.NewBuffer(nil)
	err = renderDriverConfig(bufDriverConfig, driverConfigData{ModuleVersion: bc.ModuleConfig.ModuleVersion, ModuleName: bc.ModuleConfig.ModuleName, DeviceName: bc.ModuleConfig.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: bc.ModuleConfig.ModuleName, KernelBuildDir: builder.KernelDirectory, ModuleBuildDir: builder.ModuleDirectory})
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
			ActiveDeadlineSeconds: int64Ptr(deadline + deadlineGracePeriod),
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

	return bp.copyModuleFromPodWithUID(namespace, uid)
}

func (bp *KubernetesBuildProcessor) copyModuleFromPodWithUID(namespace string, falcoBuilderUID string) error {
	namespacedClient := bp.coreV1Client.Pods(namespace)
	watch, err := namespacedClient.Watch(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", falcoBuilderUIDLabel, falcoBuilderUID),
	})
	if err != nil {
		return err
	}
	// Give it ten minutes to complete, if it doesn't give an error
	ctx, cancel := context.WithTimeout(bp.ctx, 10*time.Minute)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return errors.New("moduly copy from pod interrupted before the copy was complete")
		default:
			event := <-watch.ResultChan()
			p, ok := event.Object.(*corev1.Pod)
			if !ok {
				bp.logger.Error("unexpected type when watching pods")
				continue
			}
			if p.Status.Phase == corev1.PodPending {
				continue
			}
			if p.Status.Phase == corev1.PodRunning {
				bp.logger.Info("downloading module from pod", zap.String(falcoBuilderUIDLabel, falcoBuilderUID))
				// TODO(fntlnz): make the output directory configurable
				err = copySingleFileFromPod(bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name, builder.FalcoModuleFullPath, "/tmp/falco.ko")
				if err != nil {
					return err
				}
			}
			return nil
		}

	}
	return nil
}

func copySingleFileFromPod(podClient v1.PodsGetter, clientConfig *restclient.Config, namespace, podName, fileName, destFileName string) error {
	if len(namespace) == 0 {
		return errors.New("need a namespace to copy from pod")
	}

	if len(podName) == 0 {
		return errors.New("need a podName to copy from pod")
	}

	if len(fileName) == 0 {
		return errors.New("need a fileName to copy from pod")
	}

	reader, outStream := io.Pipe()

	options := &exec.ExecOptions{
		PodClient: podClient,
		Config:    clientConfig,
		StreamOptions: exec.StreamOptions{
			IOStreams: genericclioptions.IOStreams{
				In:     nil,
				Out:    outStream,
				ErrOut: os.Stdout, //TODO(fntlnz): necessary to deal with errors here?
			},

			Namespace: namespace,
			PodName:   podName,
		},

		Command: []string{
			"/bin/bash",
			"/module-builder/module-downloader.sh",
		},
		Executor: &exec.DefaultRemoteExecutor{},
	}

	err := options.Run()

	if err != nil {
		return err
	}

	out, err := os.Create(destFileName)
	if err != nil {
		return err
	}

	defer out.Close()

	// This (reader) is not copied until the end because we want the file to appear on the filesystem
	// only very late in the stage, when there are no errors.
	// Please don't pass the final file directly to the IOStreams otherwise we will have synchronization
	// problems with the entrypoint!
	_, err = io.Copy(out, reader)
	return err
}
