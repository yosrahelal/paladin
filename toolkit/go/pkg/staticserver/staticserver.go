package staticserver

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/tkmsgs"
)

// used to allow mocking of os.Stat in tests
var osStat = os.Stat

type StaticServer interface {
	HTTPHandler(w http.ResponseWriter, r *http.Request)
}

var _ StaticServer = &staticServer{}

type staticServer struct {
	staticPath string // path to static files
	indexPath  string // path to the index file (relative to staticPath)
	urlPrefix  string // prefix for the URL to serve static files from
}

func NewStaticServer(conf pldconf.StaticServerConfig) *staticServer {
	return &staticServer{
		staticPath: conf.StaticPath,
		indexPath:  "index.html",
		urlPrefix:  conf.URLPath,
	}
}

func (s *staticServer) HTTPHandler(w http.ResponseWriter, r *http.Request) {
	s.httpHandler(w, r)
}

// serveHTTP serves the static files in the ui directory
func (s *staticServer) httpHandler(w http.ResponseWriter, r *http.Request) {

	path, _ := filepath.Rel(s.urlPrefix, r.URL.Path)

	// prepend the path with the path to the static directory
	path = filepath.Join(s.staticPath, strings.ReplaceAll(path, "..", "_"), "/")

	// check whether a file exists at the given path
	if _, err := osStat(path); os.IsNotExist(err) {
		// file does not exist, serve index.html
		http.ServeFile(w, r, filepath.Join(s.staticPath, s.indexPath))
		return
	} else if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		log.L(r.Context()).Errorf("Failed to serve file: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(&fftypes.RESTError{
			Error: i18n.ExpandWithCode(r.Context(), i18n.MessageKey(tkmsgs.MsgUIServerFailed)),
		})
		return
	}

	// Serve the requested file directly
	http.StripPrefix(s.urlPrefix, http.FileServer(http.Dir(s.staticPath))).ServeHTTP(w, r)
}
