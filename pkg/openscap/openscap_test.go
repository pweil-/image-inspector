package openscap

import (
	"fmt"
	//docker "github.com/fsouza/go-dockerclient"
	"testing"
)

type testScanner struct {
	defaultScanner

	getRHELDistOriginal bool
	getRHELDistInt      int
	getRHELDistError    error

	getInputCVEOriginal bool
	getInputCVEString   string
	getInputCVEError    error

	oscapChrootOriginal bool
	oscapChrootByte     []byte
	oscapChrootError    error
}

func (s *testScanner) oscapChroot(oscapArgs ...string) ([]byte, error) {
	if s.oscapChrootOriginal {
		return s.defaultScanner.oscapChroot(oscapArgs...)
	}
	return s.oscapChrootByte, s.oscapChrootError
}

func (s *testScanner) getInputCVE(d int) (string, error) {
	if s.getInputCVEOriginal {
		s.defaultScanner.getInputCVE(d)
	}
	return s.getInputCVEString, s.getInputCVEError
}

func getRHELDist() (int, error) {
	return 0, fmt.Errorf("paul's error")
}

func TestScan(t *testing.T) {
	ds := &defaultScanner{}
	ds.rhelDist = getRHELDist

	tests := map[string]struct {
		ts         Scanner
		shouldFail bool
	}{
		"cant find rhel dist": {
			ts: ds,
			shouldFail: true,
		},
	}

	for k, v := range tests {
		err := v.ts.Scan()
		if v.shouldFail && err == nil {
			t.Errorf("%s expected  to cause error but it didn't", k)
		}

		// TODO check expected error
		t.Errorf("err: %v", err)
	}
}
