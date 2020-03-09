package builder

// BuilderByTarget maps targets to their builder.
var BuilderByTarget = Targets{}

// Type is a type representing targets.
type Type string

func (t Type) String() string {
	return string(t)
}

// Targets is a type representing the list of the supported targets.
type Targets map[Type]Builder

// Supported returns the list of all the supported targets.
func (t Targets) Targets() []string {
	res := []string{}
	for k := range t {
		res = append(res, k.String())
	}
	return res
}
