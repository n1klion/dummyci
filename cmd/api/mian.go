package main

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
)

const (
	port               = 3221
	logLevel           = logrus.DebugLevel
	authorizationToken = "QdbTyhFTI2mqiA94sCgYiEjgxiep1fiVUzt0wMrCHhHtoLy9ih73W4BmzkA8iO5DWzCFrzhN6fZTx4Y1uK0mVUaZByHHw7jA4Ez1ldxNanHFOlcpFtyESr1zwrJ2c4p7"
	tmpRepositoriesDir = "./tmp/repositories"
	dockerSock         = "/var/run/docker.sock"
)

var log = logrus.New()

func main() {
	log.SetLevel(logLevel)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/commit-trigger", checkAuthMiddleware(commitTriggerHandler))
	mux.HandleFunc("POST /api/debug", debugHandler)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	addr := net.JoinHostPort("localhost", strconv.Itoa(port))

	go func() {
		err := http.ListenAndServe(addr, mux)
		switch {
		case errors.Is(err, http.ErrServerClosed):
			return
		case err != nil:
			log.Error(err)
			return
		}
	}()

	log.Infof("Listening on address: %s", addr)

	<-sigChan

	log.Infof("Shutting down...")
}

func pullRepository(repo string, branch string) (string, error) {
	randomName := rand.Text()

	tmpPath := fmt.Sprintf("%s/%s", tmpRepositoriesDir, randomName)

	log.Debugf("Pulling repository: %s", repo)

	cmd := exec.Command("git", "clone", "--branch", branch, "--depth", "1", "https://github.com/"+repo+".git", tmpPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	log.Infof("Pulled repository: %s to %s successfully", repo, tmpPath)

	return randomName, nil
}

func dockerBuild(repo string, name string) error {
	dir := fmt.Sprintf("%s/%s", tmpRepositoriesDir, name)

	pr, pw := io.Pipe()

	go func() {
		tarWriter := tar.NewWriter(pw)
		defer tarWriter.Close()

		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			hdr, err := tar.FileInfoHeader(info, path)
			if err != nil {
				return err
			}
			hdr.Name, _ = filepath.Rel(dir, path)

			if err := tarWriter.WriteHeader(hdr); err != nil {
				return err
			}

			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tarWriter, f); err != nil {
					return err
				}
			}

			return nil
		})

		pw.Close()
	}()
	log.Debugf("Building docker image for repository: %s", repo)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", dockerSock)
			},
		},
		Timeout: 0,
	}

	url := fmt.Sprintf("http://unix/v1.47/build?t=%s", repo)
	req, err := http.NewRequest("POST", url, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Errorf("Failed to build docker image: %s", string(body))
		return errors.New("failed to build docker image")
	}

	io.Copy(os.Stdout, resp.Body)

	// err = printBuildLog(resp.Body)
	// if err != nil {
	// 	return err
	// }

	log.Infof("Built docker image for repository: %s successfully", repo)

	return nil
}

func printBuildLog(respBody io.Reader) error {
	scanner := bufio.NewScanner(respBody)
	for scanner.Scan() {
		line := scanner.Bytes()

		var msg struct {
			Stream string `json:"stream"`
			Aux    struct {
				ID string `json:"ID"`
			} `json:"aux"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		switch {
		case msg.Stream == "\n":
			continue
		case msg.Stream != "":
			log.Debug(msg.Stream)
		case msg.Aux.ID != "":
			log.Debugf("Built image ID: %s\n", msg.Aux.ID)
		}
	}
	return scanner.Err()
}

func deleteClonedRepositoryDir(endpoint string) {
	err := os.RemoveAll(fmt.Sprintf("%s/%s", tmpRepositoriesDir, endpoint))
	if err != nil {
		log.Errorf("Failed to delete tmp directory: %s", err)
	}
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
	repoName, err := pullRepository("n1klion/budget", "main")
	if err != nil {
		log.Errorf("Failed to pull repository: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return
	}
	defer deleteClonedRepositoryDir(repoName)

	err = dockerBuild("n1klion/budget", repoName)
	if err != nil {
		log.Errorf("Failed to build docker image for repository: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func commitTriggerHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error(err)
		return
	}

	log.Infof("Commit trigger received: %s", string(body))

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func checkAuthMiddleware(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		var token string

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, prefix) {
			token = authHeader[len(prefix):]
		}

		if token != authorizationToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		next(w, r)
	}
}
