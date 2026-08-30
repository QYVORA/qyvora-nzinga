package safety

import (
	"testing"

	"github.com/QYVORA/qyvora-nzinga/pkg/models"
)

func TestAllKnownOperationsAreAllowedAndSafe(t *testing.T) {
	ops := []OperationMetadata{
		OpCertEnumerate, OpDNSResolve, OpWhoisLookup, OpUsernameEnumerate, OpAnalyze,
	}
	for _, op := range ops {
		if op.ID == "" || op.Name == "" {
			t.Fatalf("operation missing contract fields: %+v", op)
		}
		if op.ChangesState {
			t.Fatalf("source operation %q must never change remote state", op.ID)
		}
		if !op.Reversible {
			t.Fatalf("source operation %q must be reversible", op.ID)
		}
		if op.Risk != models.RiskS1 {
			t.Fatalf("source operation %q must be risk S1", op.ID)
		}
		if !IsAllowed(op, true) {
			t.Fatalf("read-only S1 operation %q must be allowed in safe mode", op.ID)
		}
	}
}

func TestIsAllowedRejectsUnsafePosture(t *testing.T) {
	destructive := OperationMetadata{
		ID: "nzinga.test.write", Name: "write", ChangesState: true, Reversible: true, Risk: models.RiskS3,
	}
	if !IsAllowed(destructive, false) {
		t.Fatal("reversible state change may run outside safe-only posture")
	}
	if IsAllowed(destructive, true) {
		t.Fatal("safe-only posture must reject operations at risk >= S3")
	}
	if !IsAllowed(OperationMetadata{Risk: models.RiskS1, ChangesState: false, Reversible: true}, true) {
		t.Fatal("S1 read-only ops are allowed in safe mode")
	}
	if IsAllowed(OperationMetadata{Risk: models.RiskS3, ChangesState: true, Reversible: false}, false) {
		t.Fatal("irreversible risky ops are never allowed")
	}
	if IsAllowed(OperationMetadata{Risk: models.RiskS3, ChangesState: true, Reversible: false}, true) {
		t.Fatal("irreversible risky ops are never allowed")
	}
}

func TestClassValues(t *testing.T) {
	if ClassDiscovery == "" || ClassEnumerat == "" || ClassAnalysis == "" {
		t.Fatal("operation classes must be non-empty")
	}
}
