package analyzer

import (
	"bitbucket.org/zhengyuli/ntrace/analyzer/dumy"
	"testing"
)

func TestAnalyzerManager(t *testing.T) {
	analyzer := GetAnalyzer(dumy.ProtoName)
	if analyzer.Proto() != dumy.ProtoName {
		t.Errorf("Analyzer: get wrong analyzer for proto: %s.", analyzer.Proto())
	}

	analyzer = GetAnalyzer("Unknown")
	if analyzer.Proto() != dumy.ProtoName {
		t.Errorf("Analyzer: get wrong analyzer for proto: %s.", analyzer.Proto())
	}
}
