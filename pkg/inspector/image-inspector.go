package inspector

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"
	"syscall"

	"archive/tar"
	"crypto/rand"

	docker "github.com/fsouza/go-dockerclient"
	"github.com/simon3z/image-inspector/pkg/openscap"
	"golang.org/x/net/webdav"

	iicmd "github.com/simon3z/image-inspector/pkg/cmd"
)

type APIVersions struct {
	Versions []string `json:"versions"`
}

const (
	VERSION_TAG        = "v1"
	DOCKER_TAR_PREFIX  = "rootfs/"
	OWNER_PERM_RW      = 0600
	HEALTHZ_URL_PATH   = "/healthz"
	API_URL_PREFIX     = "/api"
	CONTENT_URL_PREFIX = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH  = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
	OPENSCAP_URL_PATH  = API_URL_PREFIX + "/" + VERSION_TAG + "/openscap"
	CHROOT_SERVE_PATH  = "/"
	OSCAP_CVE_DIR      = "/tmp"
)

// ImageInspector is the interface for all image inspectors.
type ImageInspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect() error
}

// defaultImageInspector is the default implementation of ImageInspector.
type defaultImageInspector struct {
	opts iicmd.ImageInspectorOptions
	meta iicmd.InspectorMetadata
}

// NewDefaultImageInspector provides a new default inspector.
func NewDefaultImageInspector(opts iicmd.ImageInspectorOptions) ImageInspector {
	return &defaultImageInspector{opts,
		*iicmd.NewInspectorMetadata(&docker.Image{})}
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) Inspect() error {
	client, err := docker.NewClient(i.opts.URI)
	if err != nil {
		return fmt.Errorf("Unable to connect to docker daemon: %v\n", err)
	}

	if _, err := client.InspectImage(i.opts.Image); err != nil {
		log.Printf("Pulling image %s", i.opts.Image)
		imagePullOption := docker.PullImageOptions{Repository: i.opts.Image}

		var imagePullAuths *docker.AuthConfigurations
		var authCfgErr error
		if imagePullAuths, authCfgErr = getAuthConfigs(i.opts.DockerCfg, i.opts.Username, i.opts.PasswordFile); authCfgErr != nil {
			return authCfgErr
		}

		// Try all the possible auth's from the config file
		var authErr error
		for _, auth := range imagePullAuths.Configs {
			if authErr = client.PullImage(imagePullOption, auth); authErr == nil {
				break
			}
		}
		if authErr != nil {
			return fmt.Errorf("Unable to pull docker image: %v\n", authErr)
		}
	} else {
		log.Printf("Image %s is available, skipping image pull", i.opts.Image)
	}

	randomName, err := generateRandomName()
	if err != nil {
		return err
	}

	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: randomName,
		Config: &docker.Config{
			Image: i.opts.Image,
			// For security purpose we don't define any entrypoint and command
			Entrypoint: []string{""},
			Cmd:        []string{""},
		},
	})
	if err != nil {
		return fmt.Errorf("Unable to create docker container: %v\n", err)
	}

	containerMetadata, err := client.InspectContainer(container.ID)
	if err != nil {
		return fmt.Errorf("Unable to get docker container information: %v\n", err)
	}

	imageMetadata, err := client.InspectImage(containerMetadata.Image)
	i.meta.Image = *imageMetadata
	if err != nil {
		return fmt.Errorf("Unable to get docker image information: %v\n", err)
	}

	if len(i.opts.DstPath) > 0 {
		err = os.Mkdir(i.opts.DstPath, 0755)
		if err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("Unable to create destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		i.opts.DstPath, err = ioutil.TempDir("/var/tmp", "image-inspector-")
		if err != nil {
			return fmt.Errorf("Unable to create temporary path: %v\n", err)
		}
	}

	reader, writer := io.Pipe()
	go handleTarStream(reader, i.opts.DstPath)

	log.Printf("Extracting image %s to %s", i.opts.Image, i.opts.DstPath)
	err = client.CopyFromContainer(docker.CopyFromContainerOptions{
		Container:    container.ID,
		OutputStream: writer,
		Resource:     "/",
	})
	if err != nil {
		return fmt.Errorf("Unable to extract container: %v\n", err)
	}

	_ = client.RemoveContainer(docker.RemoveContainerOptions{
		ID: container.ID,
	})

	supportedVersions := APIVersions{Versions: []string{VERSION_TAG}}

	var arf_body []byte
	if len(i.opts.OscapResultsArf) > 0 {
		arf_body = i.runOpenSCAP()
	}

	if len(i.opts.Serve) > 0 {
		servePath := i.opts.DstPath
		if i.opts.Chroot {
			if err := syscall.Chroot(i.opts.DstPath); err != nil {
				return fmt.Errorf("Unable to chroot into %s: %v\n", i.opts.DstPath, err)
			}
			servePath = CHROOT_SERVE_PATH
		} else {
			log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
			log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
			log.Printf("information of the hosting system.")
		}

		log.Printf("Serving image content %s on webdav://%s%s", i.opts.DstPath, i.opts.Serve, CONTENT_URL_PREFIX)

		http.HandleFunc(HEALTHZ_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok\n"))
		})

		http.HandleFunc(API_URL_PREFIX, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(supportedVersions, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.HandleFunc(METADATA_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(i.meta, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.HandleFunc(OPENSCAP_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			if (len(i.opts.OscapResultsArf) > 0) && i.meta.OpenSCAP.Status == iicmd.StatusSuccess {
				w.Write(arf_body)
			} else {
				if i.meta.OpenSCAP.Status == iicmd.StatusError {
					http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", i.meta.OpenSCAP.ErrorMessage),
						http.StatusInternalServerError)
				} else {
					http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
				}
			}
		})

		http.Handle(CONTENT_URL_PREFIX, &webdav.Handler{
			Prefix:     CONTENT_URL_PREFIX,
			FileSystem: webdav.Dir(servePath),
			LockSystem: webdav.NewMemLS(),
		})

		return http.ListenAndServe(i.opts.Serve, nil)
	}
	return nil
}

func handleTarStream(reader io.ReadCloser, destination string) {
	tr := tar.NewReader(reader)
	if tr != nil {
		err := processTarStream(tr, destination)
		if err != nil {
			log.Print(err)
		}
	} else {
		log.Printf("Unable to create image tar reader")
	}
	reader.Close()
}

func processTarStream(tr *tar.Reader, destination string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("Unable to extract container: %v\n", err)
		}

		hdrInfo := hdr.FileInfo()

		dstpath := path.Join(destination, strings.TrimPrefix(hdr.Name, DOCKER_TAR_PREFIX))
		// Overriding permissions to allow writing content
		mode := hdrInfo.Mode() | OWNER_PERM_RW

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dstpath, mode); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("Unable to create directory: %v", err)
				}
				err = os.Chmod(dstpath, mode)
				if err != nil {
					return fmt.Errorf("Unable to update directory mode: %v", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(dstpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("Unable to create file: %v", err)
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return fmt.Errorf("Unable to write into file: %v", err)
			}
			file.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, dstpath); err != nil {
				return fmt.Errorf("Unable to create symlink: %v\n", err)
			}
		case tar.TypeLink:
			target := path.Join(destination, strings.TrimPrefix(hdr.Linkname, DOCKER_TAR_PREFIX))
			if err := os.Link(target, dstpath); err != nil {
				return fmt.Errorf("Unable to create link: %v\n", err)
			}
		default:
			// For now we're skipping anything else. Special device files and
			// symlinks are not needed or anyway probably incorrect.
		}

		// maintaining access and modification time in best effort fashion
		os.Chtimes(dstpath, hdr.AccessTime, hdr.ModTime)
	}
}

func generateRandomName() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", fmt.Errorf("Unable to generate random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n), nil
}

func getAuthConfigs(dockercfg, username, password_file string) (*docker.AuthConfigurations, error) {
	imagePullAuths := &docker.AuthConfigurations{
		map[string]docker.AuthConfiguration{"": {}}}
	if dockercfg != "" {
		reader, err := os.Open(dockercfg)
		if err != nil {
			return nil, fmt.Errorf("Unable to open docker config file: %v\n", err)
		}
		if imagePullAuths, err = docker.NewAuthConfigurations(reader); err != nil {
			return nil, fmt.Errorf("Unable to parse docker config file: %v\n", err)
		}
		if len(imagePullAuths.Configs) == 0 {
			return nil, fmt.Errorf("No auths were found in the given dockercfg file\n")
		}
	}
	if username != "" {
		token, err := ioutil.ReadFile(password_file)
		if err != nil {
			return nil, fmt.Errorf("Unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{
			map[string]docker.AuthConfiguration{"": {Username: username, Password: string(token)}}}
	}

	return imagePullAuths, nil
}

func (i *defaultImageInspector) runOpenSCAP() []byte {
	log.Printf("OpenSCAP scanning %s", i.opts.DstPath)
	scanner := openscap.NewDefaultScanner(i.opts.DstPath, OSCAP_CVE_DIR,
		i.opts.OscapResultsArf, &i.meta.Image)
	err := scanner.Scan()
	if err != nil {
		fmt.Printf("Unable to run OpenSCAP: %v\n", err)
	} else {
		arf_body, err := ioutil.ReadFile(i.opts.OscapResultsArf)
		if err != nil {
			log.Printf("Unable to read OpenSCAP result file: %v\n", err)
		} else {
			i.meta.OpenSCAP.Status = iicmd.StatusSuccess
			return arf_body
		}
	}
	i.meta.OpenSCAP.SetError(err)
	return []byte("")
}
