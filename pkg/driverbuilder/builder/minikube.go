package builder

// TargetTypeMinikube identifies the Minikube target.
const TargetTypeMinikube Type = "minikube"

func init() {
	BuilderByTarget[TargetTypeMinikube] = &vanilla{}
}
