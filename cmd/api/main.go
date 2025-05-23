package main

import (
	"archive/tar"
	"context"
	"crypto/rand"
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
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/moby/buildkit/session"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
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
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	dir := fmt.Sprintf("%s/%s", tmpRepositoriesDir, name)

	buildContext, err := createBuildContext(dir)
	if err != nil {
		return err
	}

	log.Debugf("Building docker image for repository: %s", repo)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*15)
	defer cancel()

	s, err := session.NewSession(ctx, "buildkit-session")
	if err != nil {
		return fmt.Errorf("failed to create buildkit session: %w", err)
	}

	dialer := func(ctx context.Context, proto string, meta map[string][]string) (net.Conn, error) {
		return cli.DialHijack(ctx, "/session", proto, meta)
	}

	eg, sessionCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return s.Run(sessionCtx, dialer)
	})

	resp, err := cli.ImageBuild(context.Background(), buildContext, types.ImageBuildOptions{
		Tags:        []string{repo},
		Remove:      true,
		ForceRemove: true,
		SessionID:   s.ID(),
		Version:     types.BuilderBuildKit,
		PullParent:  true,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		cancel()
		return fmt.Errorf("failed to read build output: %w", err)
	}

	cancel()
	if err := eg.Wait(); err != nil && err != context.Canceled {
		return fmt.Errorf("session error: %w", err)
	}

	log.Infof("Built docker image for repository: %s successfully", repo)

	return nil
}

func createBuildContext(dir string) (io.Reader, error) {
	pr, pw := io.Pipe()
	go func() {
		tarWriter := tar.NewWriter(pw)
		defer tarWriter.Close()

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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

		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()

	return pr, nil
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
