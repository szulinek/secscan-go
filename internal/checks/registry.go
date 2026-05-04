package checks

type Registry struct {
	modules []Module
}

func NewRegistry(modules ...Module) Registry {
	return Registry{modules: modules}
}

func (r Registry) Modules() []Module {
	modules := make([]Module, len(r.modules))
	copy(modules, r.modules)
	return modules
}
