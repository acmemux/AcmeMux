package httpapi

import (
	"context"
	"errors"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
)

type inertRuntimeInspector struct{}

func (inertRuntimeInspector) Inspect(context.Context, string) (acmeruntime.Observation, error) {
	return acmeruntime.Observation{}, errors.New("unexpected runtime inspection")
}

func (inertRuntimeInspector) Verify(context.Context, acmeruntime.Observation) (acmeruntime.Observation, error) {
	return acmeruntime.Observation{}, errors.New("unexpected runtime verification")
}

type inertRuntimeSelections struct{}

func (inertRuntimeSelections) Load(context.Context) (acmeruntime.Selection, error) {
	return acmeruntime.Selection{}, acmeruntime.ErrNoSelection
}

func (inertRuntimeSelections) Save(context.Context, acmeruntime.Selection) error {
	return errors.New("unexpected runtime selection save")
}

func testRuntimeDependencies() RuntimeDependencies {
	return RuntimeDependencies{
		Inspector:  inertRuntimeInspector{},
		Selections: inertRuntimeSelections{},
		Classify: func(acmeruntime.Observation) compatibility.Result {
			return compatibility.Result{Code: compatibility.CodeUnknownIdentity}
		},
	}
}
