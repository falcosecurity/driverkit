package modulebuilder

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kube "k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/batch/v1"
)

const KubernetesBuildProcessorName = "kubernetes"

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
			err := createKubernetesJob(bp.kubeClient.BatchV1().Jobs("default"))
			if err != nil {
				bp.logger.Error("error creating the kubernetes job", zap.Error(err))
			}
		}
	}
	return nil
}

const builderBaseImage = "docker.io/library/ubuntu:18.04"

func int32Ptr(i int32) *int32 { return &i }
func int64Ptr(i int64) *int64 { return &i }

func createKubernetesJob(jobClient v1.JobInterface) error {
	buildCmd := []string{
		"/usr/bin/whoami",
	}

	name := "falco-builder" // TODO(fntlnz): generate this
	namespace := "default" // TODO(fntlnz): make this configurable
	commonMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
	}

	job := &batchv1.Job{
		ObjectMeta: commonMeta,
		Spec: batchv1.JobSpec{
			ActiveDeadlineSeconds:   int64Ptr(100),
			TTLSecondsAfterFinished: int32Ptr(5),
			Parallelism:             int32Ptr(1),
			Completions:             int32Ptr(1),
			BackoffLimit:            int32Ptr(1),
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: commonMeta,
				Spec: apiv1.PodSpec{
					Containers: []apiv1.Container{
						{
							Name:    name,
							Image:   builderBaseImage,
							Command: buildCmd,
							Resources: apiv1.ResourceRequirements{
								Requests: apiv1.ResourceList{
									apiv1.ResourceCPU:    resource.MustParse("1000m"),
									apiv1.ResourceMemory: resource.MustParse("2000Mi"),
								},
								Limits: apiv1.ResourceList{
									apiv1.ResourceCPU:    resource.MustParse("4"),
									apiv1.ResourceMemory: resource.MustParse("4G"),
								},
							},
						},
					},
					RestartPolicy: "Never",
				},
			},
		},
	}

	_, err := jobClient.Create(job)
	if err != nil {
		return err
	}
	return nil
}
