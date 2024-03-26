// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driverbuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/falcosecurity/driverkit/pkg/signals"

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
	slog.Debug("doing a new kubernetes build")
	return bp.buildModule(b)
}

func (bp *KubernetesBuildProcessor) buildModule(b *builder.Build) error {
	deadline := int64(bp.timeout)
	namespace := bp.namespace
	uid := uuid.NewUUID()
	name := fmt.Sprintf("driverkit-%s", string(uid))

	podClient := bp.coreV1Client.Pods(namespace)
	configClient := bp.coreV1Client.ConfigMaps(namespace)

	kr := b.KernelReleaseFromBuildConfig()

	// create a builder based on the chosen build type
	v, err := builder.Factory(b.TargetType)
	if err != nil {
		return err
	}

	c := b.ToConfig()

	libsDownloadScript, err := builder.LibsDownloadScript(c)
	if err != nil {
		return err
	}

	kernelDownloadScript, err := builder.KernelDownloadScript(v, c.KernelUrls, kr)
	if err != nil {
		return err
	}

	// generate the build script from the builder
	res, err := builder.Script(v, c, kr)
	if err != nil {
		return err
	}

	// We run a script that downloads libs,
	// download and extracts kernelURLs saving its output to KERNELDIR env variable,
	// then finally runs the build script.
	res = fmt.Sprintf("%s\nexport KERNELDIR=$(%s)\n%s", libsDownloadScript, kernelDownloadScript, res)

	if c.ModuleFilePath != "" {
		res = fmt.Sprintf("%s\n%s", "touch "+moduleLockFile, res)
		res = fmt.Sprintf("%s\n%s", res, "rm "+moduleLockFile)
	}
	if c.ProbeFilePath != "" {
		res = fmt.Sprintf("%s\n%s", "touch "+probeLockFile, res)
		res = fmt.Sprintf("%s\n%s", res, "rm "+probeLockFile)
	}

	// Append a script to the entrypoint to wait
	// for the module to be ready before exiting PID 1
	res = fmt.Sprintf("%s\n%s", res, waitForLockScript)

	buildCmd := []string{
		"/bin/bash",
		"-l",
		"/driverkit/driverkit.sh",
	}

	commonMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels: map[string]string{
			falcoBuilderUIDLabel: string(uid),
		},
	}

	configDecoded, err := base64.StdEncoding.DecodeString(b.KernelConfigData)
	if err != nil {
		return err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: commonMeta,
		Data: map[string]string{
			"download-libs.sh":    libsDownloadScript,
			"download-headers.sh": kernelDownloadScript,
			"driverkit.sh":        res,
			"kernel.config":       string(configDecoded),
			"downloader.sh":       waitForLockAndCat,
			"unlock.sh":           deleteLock,
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

	builderImage := b.GetBuilderImage()

	secuContext := corev1.PodSecurityContext{
		RunAsUser: &bp.runAsUser,
	}

	imagePullSecrets := make([]corev1.LocalObjectReference, 0)
	if bp.imagePullSecret != "" {
		imagePullSecrets = append(imagePullSecrets, corev1.LocalObjectReference{Name: bp.imagePullSecret})
	}

	pod := &corev1.Pod{
		ObjectMeta: commonMeta,
		Spec: corev1.PodSpec{
			ActiveDeadlineSeconds: pointer.Int64Ptr(deadline),
			RestartPolicy:         corev1.RestartPolicyNever,
			SecurityContext:       &secuContext,
			ImagePullSecrets:      imagePullSecrets,
			NodeSelector:          map[string]string{corev1.LabelArchStable: kr.Architecture.String()},
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

	slog.
		With("name", pod.Name, "spec", pod.Spec.String()).
		Debug("starting pod")

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
	return bp.copyModuleAndProbeFromPodWithUID(ctx, c, b, namespace, string(uid))
}

func (bp *KubernetesBuildProcessor) copyModuleAndProbeFromPodWithUID(ctx context.Context, c builder.Config, build *builder.Build, namespace string, falcoBuilderUID string) error {
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
				slog.Error("unexpected type when watching pods")
				continue
			}
			if p.Status.Phase == corev1.PodPending {
				continue
			}
			if p.Status.Phase == corev1.PodRunning {
				slog.With(falcoBuilderUIDLabel, falcoBuilderUID).Info("start downloading module and probe from pod")
				if c.ModuleFilePath != "" {
					err = copySingleFileFromPod(c.ModuleFilePath, bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name, c.ToDriverFullPath(), moduleLockFile)
					if err != nil {
						return err
					}
					slog.Info("Kernel Module extraction successful")
				}
				if c.ProbeFilePath != "" {
					err = copySingleFileFromPod(c.ProbeFilePath, bp.coreV1Client, bp.clientConfig, p.Namespace, p.Name, c.ToProbeFullPath(), probeLockFile)
					if err != nil {
						return err
					}
					slog.Info("Probe Module extraction successful")
				}
				err = unlockPod(bp.coreV1Client, bp.clientConfig, p)
				if err != nil {
					return err
				}
				slog.With(falcoBuilderUIDLabel, falcoBuilderUID).Info("completed downloading from pod")
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
