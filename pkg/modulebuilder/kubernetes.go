package modulebuilder

import (
	"bytes"
	"context"
	"fmt"

	"github.com/falcosecurity/build-service/pkg/modulebuilder/builder"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kube "k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

const KubernetesBuildProcessorName = "kubernetes"

var builderBaseImage = "docker.io/falcosecurity/falco-builder-service-base:latest" // This is overwritten when using the Makefile to build
const falcoBuilderUIdLabel = "org.falcosecurity/falco-builder-uid"

type KubernetesBuildProcessor struct {
	buildsch   chan Build
	ctx        context.Context
	logger     *zap.Logger
	kubeClient *kube.Clientset
	bufferSize int
}

// NewKubernetesBuildProcessor constructs a KubernetesBuildProcessor
// starting from a kubernetes.Clientset. bufferSize represents the length of the
// channel we use to do the builds. A bigger bufferSize will mean that we can save more Builds
// for processing, however setting this to a big value will have impacts
func NewKubernetesBuildProcessor(kubeClient *kube.Clientset, bufferSize int) *KubernetesBuildProcessor {
	buildsch := make(chan Build, bufferSize)
	return &KubernetesBuildProcessor{
		buildsch:   buildsch,
		ctx:        context.TODO(),
		logger:     zap.NewNop(),
		kubeClient: kubeClient,
		bufferSize: bufferSize,
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
		select {
		case <-bp.ctx.Done():
			bp.logger.Info("graceful stop of the kubernetes build processor")
			return nil
		default:
			bp.logger.Info("doing a build", zap.String("type", string(b.BuildType)))
			// TODO(fntlnz): make namespace configurable
			podClient := bp.kubeClient.CoreV1().Pods("default")
			configClient := bp.kubeClient.CoreV1().ConfigMaps("default")
			err := buildOnKubernetes(bp.ctx, podClient, configClient, b)
			if err != nil {
				bp.logger.Error("error creating the kubernetes job", zap.Error(err))
			}
		}
	}
	return nil
}

func int64Ptr(i int64) *int64 { return &i }

func buildOnKubernetes(ctx context.Context, podClient v1.PodInterface, configClient v1.ConfigMapInterface, build Build) error {

	deadline := int64(1000)
	deadlineGracePeriod := int64(20)

	v, err := builder.Factory(build.BuildType)
	if err != nil {
		return err
	}

	bc := builder.BuilderConfig{
		ModuleConfig: builder.ModuleConfig{
			ModuleVersion:   "dev",                                      // TODO: make this configurable per request
			ModuleName:      "falco",                                    // TODO: make this configurable at startup
			DeviceName:      "falco",                                    // TODO: make this configurable at startup
			DownloadBaseURL: "https://github.com/draios/sysdig/archive", // TODO: make this configurable at startup
		},
		KernelConfigData: build.KernelConfigData, // TODO: make this configurable per request
		KernelVersion:    build.KernelVersion,
	}
	res, err := v.Script(bc)
	if err != nil {
		return err
	}

	buildCmd := []string{
		"/bin/bash",
		"/module-builder/module-builder.sh",
	}

	name := "falco-builder" // TODO(fntlnz): generate this
	namespace := "default"  // TODO(fntlnz): make this configurable
	uid := "generate-a-uid" //todo(fntlnz): generate an uid here
	commonMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			falcoBuilderUIdLabel: uid,
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

	cm := &corev1.ConfigMap{
		ObjectMeta: commonMeta,
		Data: map[string]string{
			"module-builder.sh":      res,
			"kernel.config":          prepareKernelConfig(build.KernelConfigData, bc.KernelVersion),
			"module-Makefile":        bufMakefile.String(),
			"module-driver-config.h": bufDriverConfig.String(),
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: commonMeta,
		Spec: corev1.PodSpec{
			ActiveDeadlineSeconds: int64Ptr(deadline + deadlineGracePeriod),
			Containers: []corev1.Container{
				{
					Name:    name,
					Image:   builderBaseImage,
					Command: buildCmd,

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

	//watch, err := podClient.Watch(metav1.ListOptions{
	//	LabelSelector: fmt.Sprintf("%s=%s", falcoBuilderUIdLabel, uid),
	//})
	//
	//if err != nil {
	//	return err
	//}
	//for event := range watch.ResultChan() {
	//	select {
	//	case <-ctx.Done():
	//		return podClient.Delete(name,nil)
	//	default:
	//		fmt.Printf("Type: %v\n", event.Type)
	//		p, ok := event.Object.(*corev1.Pod)
	//		if !ok {
	//			fmt.Println("unexpected type")
	//		}
	//		fmt.Println(p.Status.ContainerStatuses)
	//		fmt.Println(p.Status.Phase)
	//
	//		// TODO(fntlnz): once status is ready, start executing the build steps
	//	}
	//
	//}
	return nil
}
