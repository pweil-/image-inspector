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

func (s *testScanner) getRHELDist() (int, error) {
	if s.getRHELDistOriginal {
		return s.defaultScanner.getRHELDist()
	}
	return s.getRHELDistInt, s.getRHELDistError
}

func TestScan(t *testing.T) {
	ds := &defaultScanner{"chrootPath", "cveDir", "arfResultFileName", nil}

	tests := map[string]struct {
		ts         *testScanner
		shouldFail bool
	}{
		"cant find rhel dist": {
			ts: &testScanner{
				getRHELDistOriginal: false,
				getRHELDistInt:      0,
				getRHELDistError:    fmt.Errorf("could not find RHEL dist"),
			},
			shouldFail: true,
		},
	}

	for k, v := range tests {
		v.ts.defaultScanner = *ds
		err := v.ts.Scan()
		if v.shouldFail && err == nil {
			t.Errorf("%s expected  to cause error but it didn't", k)
		}
	}
}
