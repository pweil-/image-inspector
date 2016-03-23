package main

import (
	"flag"
	"log"

	iicmd "github.com/simon3z/image-inspector/pkg/cmd"
	ii "github.com/simon3z/image-inspector/pkg/inspector"
)

func main() {
	inspectorOptions := iicmd.NewDefaultImageInspectorOptions()

	flag.StringVar(&inspectorOptions.URI, "docker", inspectorOptions.URI, "Daemon socket to connect to")
	flag.StringVar(&inspectorOptions.Image, "image", inspectorOptions.Image, "Docker image to inspect")
	flag.StringVar(&inspectorOptions.DstPath, "path", inspectorOptions.DstPath, "Destination path for the image files")
	flag.StringVar(&inspectorOptions.Serve, "serve", inspectorOptions.Serve, "Host and port where to serve the image with webdav")
	flag.BoolVar(&inspectorOptions.Chroot, "chroot", inspectorOptions.Chroot, "Change root when serving the image with webdav")
	flag.StringVar(&inspectorOptions.DockerCfg, "dockercfg", inspectorOptions.DockerCfg, "Location of the docker configuration file")
	flag.StringVar(&inspectorOptions.Username, "username", inspectorOptions.Username, "username for authenticating with the docker registry")
	flag.StringVar(&inspectorOptions.PasswordFile, "password-file", inspectorOptions.PasswordFile, "Location of a file that contains the password for authentication with the docker registry")
	flag.StringVar(&inspectorOptions.OscapResultsArf, "openscap-results-arf", inspectorOptions.OscapResultsArf, "Run an OpenSCAP Scan on the inspected image and publish the reports. This value is also the reports location.")

	flag.Parse()

	if err := inspectorOptions.Validate(); err != nil {
		log.Fatal(err)
	}

	inspector := ii.NewDefaultImageInspector(*inspectorOptions)
	if err := inspector.Inspect(); err != nil {
		log.Fatalf("Error inspecting image: %v", err)
	}
}
