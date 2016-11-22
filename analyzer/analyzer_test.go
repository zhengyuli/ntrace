package analyzer

import (
	"github.com/zhengyuli/ntrace/analyzer/http"
	"github.com/zhengyuli/ntrace/analyzer/tcp"
	"testing"
)

func TestAnalyzer(t *testing.T) {
	analyzer := GetAnalyzer(http.ProtoName)
	if analyzer.Proto() != http.ProtoName {
		t.Errorf("Analyzer: get wrong analyzer for proto: %s.", analyzer.Proto())
	}

	analyzer = GetAnalyzer(tcp.ProtoName)
	if analyzer.Proto() != tcp.ProtoName {
		t.Errorf("Analyzer: get wrong analyzer for proto: %s.", analyzer.Proto())
	}

	analyzer = GetAnalyzer("Unknown")
	if analyzer != nil {
		t.Errorf("Analyzer: get wrong analyzer for proto: %s.", analyzer.Proto())
	}
}
