package openscap

import (
	"fmt"
	docker "github.com/fsouza/go-dockerclient"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
)

const (
	CPE                = "oval:org.open-scap.cpe.rhel:def:"
	CPE_DICT           = "/usr/share/openscap/cpe/openscap-cpe-oval.xml"
	CVE_URL            = "https://www.redhat.com/security/data/metrics/ds/"
	DIST_CVE_NAME_FMT  = "com.redhat.rhsa-RHEL%d.ds.xml.bz2"
	ARF_RESULT_FILE    = "results-arf.xml"
	TMP_DIR            = "/tmp"
	LINUX              = "Linux"
	IMAGE_SHORT_ID_LEN = 11
)

var (
	RHEL_DIST_NUMBERS = [...]int{5, 6, 7}
)

// Scanner is the interface of OpenSCAP scanner
type Scanner interface {
	// Scan will scan
	Scan() error
}

type defaultScanner struct {
	// ChrootPath is the path where the image to be scanned is mounted
	ChrootPath string
	// CVEDir is the directory where the CVE file is saved
	CVEDir string
	// ArfResultFileName is the name of the arf report file
	ArfResultFileName string
	// Image is the metadata of the inspected image
	Image *docker.Image
}

func NewDefaultScanner(chrootPath string, cveDir string,
	arfResultFileName string, image *docker.Image) Scanner {
	return &defaultScanner{chrootPath, cveDir, arfResultFileName, image}
}

func (s *defaultScanner) getRHELDist() (int, error) {
	for _, dist := range RHEL_DIST_NUMBERS {
		output, err := s.oscapChroot(s.ChrootPath, "oval", "eval", "--id",
			fmt.Sprintf("%s%d", CPE, dist), CPE_DICT)
		if err != nil {
			return 0, err
		}
		if strings.Contains(string(output), fmt.Sprintf("%s%d: true", CPE, dist)) {
			return dist, nil
		}
	}
	return 0, fmt.Errorf("could not find RHEL dist")
}

func (s *defaultScanner) getInputCVE(dist int) (string, error) {
	cveName := fmt.Sprintf(DIST_CVE_NAME_FMT, dist)
	cveFileName := path.Join(s.CVEDir, cveName)
	cveURL, _ := url.Parse(CVE_URL)
	cveURL.Path = path.Join(cveURL.Path, cveName)

	out, err := os.Create(cveFileName)
	if err != nil {
		return "", fmt.Errorf("Could not create file %s: %v\n", cveFileName, err)
	}
	defer out.Close()

	resp, err := http.Get(cveURL.String())
	if err != nil {
		return "", fmt.Errorf("Could not download file %s: %v\n", cveURL, err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	return cveFileName, err
}

func (s *defaultScanner) setOscapChrootEnv() error {
	os.Setenv("OSCAP_PROBE_ROOT", s.ChrootPath)

	out, err := exec.Command("chroot", s.ChrootPath, "uname", "-a").Output()
	if err != nil {
		return fmt.Errorf("Unable to run uname -a %v", err)
	}
	info := strings.Split(string(out), " ")
	os.Setenv("OSCAP_PROBE_OS_VERSION", info[2])
	os.Setenv("OSCAP_PROBE_ARCHITECTURE", s.Image.Config.Labels["Architecture"])
	os.Setenv("OSCAP_PROBE_OS_NAME", LINUX)
	os.Setenv("OSCAP_PROBE_PRIMARY_HOST_NAME",
		fmt.Sprintf("docker-image-%s", s.Image.ID[:IMAGE_SHORT_ID_LEN]))

	return nil
}

// Wrapper function for executing oscap
func (s *defaultScanner) oscapChroot(oscapArgs ...string) ([]byte, error) {
	if err := s.setOscapChrootEnv(); err != nil {
		return nil, fmt.Errorf("Unable to set env variables in oscapChroot: %v", err)
	}
	cmd := exec.Command("oscap", oscapArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 2 {
				// Error code 2 means that OpenSCAP had failed rules
				// For our purpose this means success
				return out, nil
			}
			return out, fmt.Errorf("OpenSCAP error: %d: %v\nInput:\n%s\nOutput:\n%s\n",
				waitStatus.ExitStatus(), err, oscapArgs, string(out))
		}
	}
	return out, err
}

func (s *defaultScanner) Scan() error {
	rhelDist, err := s.getRHELDist()
	if err != nil {
		return fmt.Errorf("Unable to get RHEL distribution number: %v\n", err)
	}

	cveFileName, err := s.getInputCVE(rhelDist)
	if err != nil {
		return fmt.Errorf("Unable to retreive the CVE file: %v\n", err)
	}

	_, err = s.oscapChroot("xccdf", "eval",
		"--results-arf", s.ArfResultFileName,
		cveFileName)
	return err
}
