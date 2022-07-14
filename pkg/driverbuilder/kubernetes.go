package driverbuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/falcosecurity/driverkit/pkg/signals"
	"os"
	"time"

	logger "github.com/sirupsen/logrus"

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

const falcoBuilderUIDLabel = "org.falcosecurity/driverkit-uid"

type KubernetesBuildProcessor struct {
	coreV1Client    v1.CoreV1Interface
	clientConfig    *restclient.Config
	runAsUser       int64
	namespace       string
	imagePullSecret string
	timeout         int
	proxy           string
}

// NewKubernetesBuildProcessor constructs a KubernetesBuildProcessor
// starting from a kubernetes.Clientset. bufferSize represents the length of the
// channel we use to do the builds. A bigger bufferSize will mean that we can save more Builds
// for processing, however setting this to a big value will have impacts
func NewKubernetesBuildProcessor(corev1Client v1.CoreV1Interface, clientConfig *restclient.Config, runAsUser int64, namespace string, imagePullSecret string, timeout int, proxy string) *KubernetesBuildProcessor {
	return &KubernetesBuildProcessor{
		coreV1Client:    corev1Client,
		clientConfig:    clientConfig,
		runAsUser:       runAsUser,
		namespace:       namespace,
		imagePullSecret: imagePullSecret,
		timeout:         timeout,
		proxy:           proxy,
	}
}

func (bp *KubernetesBuildProcessor) String() string {
	return KubernetesBuildProcessorName
}

func (bp *KubernetesBuildProcessor) Start(b *builder.Build) error {
	logger.Debug("doing a new kubernetes build")
	return bp.buildModule(b)
}

func (bp *KubernetesBuildProcessor) buildModule(build *builder.Build) error {
	deadline := int64(bp.timeout)
	namespace := bp.namespace
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))

	podClient := bp.coreV1Client.Pods(namespace)
	configClient := bp.coreV1Client.ConfigMaps(namespace)

	kr := build.KernelReleaseFromBuildConfig()

	// create a builder based on the chosen build type
	v, err := builder.Factory(build.TargetType)
	if err != nil {
		return err
	}

	c := builder.Config{
		DriverName:      build.ModuleDriverName,
		DeviceName:      build.ModuleDeviceName,
		DownloadBaseURL: "https://github.com/falcosecurity/libs/archive", // TODO: make this configurable
		Build:           build,
	}

	// generate the build script from the builder
	res, err := builder.Script(v, c, kr)
	if err != nil {
		return err
	}

	if builder.ModuleFullPath != "" {
		res = fmt.Sprintf("%s\n%s", "touch "+moduleLockFile, res)
		res = fmt.Sprintf("%s\n%s", res, "rm "+moduleLockFile)
	}
	if builder.ProbeFullPath != "" {
		res = fmt.Sprintf("%s\n%s", "touch "+probeLockFile, res)
		res = fmt.Sprintf("%s\n%s", res, "rm "+probeLockFile)
	}

	// Append a script to the entrypoint to wait
	// for the module to be ready before exiting PID 1
	res = fmt.Sprintf("%s\n%s", res, waitForLockScript)

	buildCmd := []string{
		"/bin/bash",
		"/driverkit/driverkit.sh",
	}

	commonMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			falcoBuilderUIDLabel: string(uid),
		},
	}

	// Prepare driver config template
	bufFillDriverConfig := bytes.NewBuffer(nil)
	err = renderFillDriverConfig(bufFillDriverConfig, driverConfigData{DriverVersion: c.Build.DriverVersion, DriverName: c.DriverName, DeviceName: c.DeviceName})
	if err != nil {
		return err
	}

	// Prepare makefile template
	bufMakefile := bytes.NewBuffer(nil)
	err = renderMakefile(bufMakefile, makefileData{ModuleName: c.DriverName, ModuleBuildDir: builder.DriverDirectory})
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
			"driverkit.sh":          res,
			"kernel.config":         string(configDecoded),
			"module-Makefile":       bufMakefile.String(),
			"fill-driver-config.sh": bufFillDriverConfig.String(),
			"downloader.sh":         waitForLockAndCat,
			"unlock.sh":             deleteLock,
		},
	}
	// Construct environment variable array of corev1.EnvVar
	var envs []corev1.EnvVar
	// Add http_porxy and https_proxy environment variable
	if bp.proxy != "" {
		envs = append(envs,
			corev1.EnvVar{
				Name:  "http_proxy",
				Value: bp.proxy,
			},
			corev1.EnvVar{
				Name:  "https_proxy",
				Value: bp.proxy,
			},
		)
	}

	builderImage := build.GetBuilderImage()

	secuContext := corev1.PodSecurityContext{
		RunAsUser: &bp.runAsUser,
	}
	pod := &corev1.Pod{
		ObjectMeta: commonMeta,
		Spec: corev1.PodSpec{
			ActiveDeadlineSeconds: pointer.Int64Ptr(deadline),
			RestartPolicy:         corev1.RestartPolicyNever,
			SecurityContext:       &secuContext,
			ImagePullSecrets:      []corev1.LocalObjectReference{{Name: bp.imagePullSecret}},
			Containers: []corev1.Container{
				{
					Name:            name,
					Image:           builderImage,
					Command:         buildCmd,
					Env:             envs,
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
							Name:      "driverkit",
							MountPath: "/driverkit",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "driverkit",
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

	ctx := context.Background()
	ctx = signals.WithStandardSignals(ctx)
	_, err = configClient.Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	defer configClient.Delete(ctx, cm.Name, metav1.DeleteOptions{})
	_, err = podClient.Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	defer podClient.Delete(ctx, pod.Name, metav1.DeleteOptions{})
	return bp.copyModuleAndProbeFromPodWithUID(ctx, build, namespace, string(uid))
}

func (bp *KubernetesBuildProcessor) copyModuleAndProbeFromPodWithUID(ctx context.Context, build *builder.Build, namespace string, falcoBuilderUID string) error {
	namespacedClient := bp.coreV1Client.Pods(namespace)
	watch, err := namespacedClient.Watch(ctx, metav1.ListOptions{
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
				logger.WithField(falcoBuilderUIDLabel, falcoBuilderUID).Info("start downloading module and probe from pod")
				if builder.ModuleFullPath != "" {
					err = copySingleFileFromPod(build.ModuleFilePath, bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name, builder.ModuleFullPath, moduleLockFile)
					if err != nil {
						return err
					}
					logger.Info("Kernel Module extraction successful")
				}
				if builder.ProbeFullPath != "" {
					err = copySingleFileFromPod(build.ProbeFilePath, bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name, builder.ProbeFullPath, probeLockFile)
					if err != nil {
						return err
					}
					logger.Info("Probe Module extraction successful")
				}
				err = unlockPod(bp.coreV1Client, bp.clientConfig, p)
				if err != nil {
					return err
				}
				logger.WithField(falcoBuilderUIDLabel, falcoBuilderUID).Info("completed downloading from pod")
			}
			return nil
		}
	}
}

func unlockPod(podClient v1.PodsGetter, clientConfig *restclient.Config, pod *corev1.Pod) error {
	options := &exec.ExecOptions{
		PodClient: podClient,
		Config:    clientConfig,
		StreamOptions: exec.StreamOptions{
			IOStreams: genericclioptions.IOStreams{
				Out:    bytes.NewBuffer([]byte{}),
				ErrOut: bytes.NewBuffer([]byte{}),
			},
			Stdin:     false,
			Namespace: pod.Namespace,
			PodName:   pod.Name,
		},
		Command: []string{
			"/bin/bash",
			"/driverkit/unlock.sh",
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

func copySingleFileFromPod(dstFile string, podClient v1.PodsGetter, clientConfig *restclient.Config, namespace string, podName string, fileNameToCopy string, lockFilename string) error {
	if len(namespace) == 0 {
		return errors.New("need a namespace to copy from pod")
	}

	if len(podName) == 0 {
		return errors.New("need a podName to copy from pod")
	}

	out, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer out.Close()

	options := &exec.ExecOptions{
		PodClient: podClient,
		Config:    clientConfig,
		StreamOptions: exec.StreamOptions{
			IOStreams: genericclioptions.IOStreams{
				Out:    out,
				ErrOut: bytes.NewBuffer([]byte{}), //TODO(fntlnz): necessary to deal with errors here?
			},
			Stdin:     false,
			Namespace: namespace,
			PodName:   podName,
		},

		Command: []string{
			"/bin/bash",
			"/driverkit/downloader.sh",
			fileNameToCopy,
			lockFilename,
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
