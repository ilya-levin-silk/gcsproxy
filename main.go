package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gorilla/mux"
	"google.golang.org/api/option"
)

const (
	default_bind = "0.0.0.0:8080"
)

var (
	bind         = flag.String("b", "", fmt.Sprintf("Bind address, Accept value from env var BIND in format %s", default_bind))
	buckets      = flag.String("B", "", "Comma-separated list of allowed buckets, Accept value from env var BUCKETS")
	verbose      = flag.Bool("v", false, "Show access log")
	credentials  = flag.String("c", "", "The path to the keyfile. If not present, client will use your default application credentials.")
	defaultIndex = flag.String("i", "", "The default index file to serve.")
	defaultRoot  = flag.String("r", "", "The default root file to serve. like /bucket/index.html. taken from env var INDEX_FILE")
)

var client *storage.Client
var allowed_buckets []string

func handleError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrObjectNotExist) {
		http.Error(w, err.Error(), http.StatusNotFound)
	} else {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func header(r *http.Request, key string) (string, bool) {
	if r.Header == nil {
		return "", false
	}
	if candidate := r.Header[key]; len(candidate) > 0 {
		return candidate[0], true
	}
	return "", false
}

func setStrHeader(w http.ResponseWriter, key string, value string) {
	if value != "" {
		w.Header().Add(key, value)
	}
}

func setIntHeader(w http.ResponseWriter, key string, value int64) {
	if value > 0 {
		w.Header().Add(key, strconv.FormatInt(value, 10))
	}
}

func setTimeHeader(w http.ResponseWriter, key string, value time.Time) {
	if !value.IsZero() {
		w.Header().Add(key, value.UTC().Format(http.TimeFormat))
	}
}

type wrapResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *wrapResponseWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.status = status
}

func wrapper(fn func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proc := time.Now()
		writer := &wrapResponseWriter{
			ResponseWriter: w,
			status:         http.StatusOK,
		}
		fn(writer, r)
		addr := r.RemoteAddr
		if ip, found := header(r, "X-Forwarded-For"); found {
			addr = ip
		}
		if *verbose {
			log.Printf("[%s] %.3f %d %s %s",
				addr,
				time.Now().Sub(proc).Seconds(),
				writer.status,
				r.Method,
				r.URL,
			)
		}
	}
}

func fetchObjectAttrs(ctx context.Context, bucket, object string) (*storage.ObjectAttrs, error) {
	var err error
	var indexAppended bool
	if object == "" && *defaultIndex != "" {
		object, err = url.JoinPath(object, *defaultIndex)
		if err != nil {
			return nil, err
		}
		indexAppended = true
	}

	attrs, err := client.Bucket(bucket).Object(strings.TrimSuffix(object, "/")).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			if *defaultIndex == "" || indexAppended {
				return nil, err
			}
			object, err = url.JoinPath(object, *defaultIndex)
			if err != nil {
				return nil, err
			}
			return client.Bucket(bucket).Object(object).Attrs(ctx)
		}
		return nil, err
	}
	return attrs, nil
}

func root(w http.ResponseWriter, r *http.Request) {
	// redirect to the default Root file
	if *defaultRoot != "" {
		http.Redirect(w, r, *defaultRoot, http.StatusMovedPermanently)
		return
	}
	http.Error(w, "¯\\_(ツ)_/¯", http.StatusNotFound)
}

func proxy(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)

	// the allowed buckets is passed in environment variable in format BUCKETS=name,name,name

	// check if the bucket is allowed
	allowed := false
	for _, b := range allowed_buckets {
		if b == params["bucket"] {
			allowed = true
			break
		}
	}

	if !allowed {
		// return 404 if the bucket is not allowed
		http.Error(w, "¯\\_(ツ)_/¯", http.StatusNotFound)
		return
	}

	attrs, err := fetchObjectAttrs(r.Context(), params["bucket"], params["object"])
	if err != nil {
		handleError(w, err)
		return
	}
	if lastStrs, ok := r.Header["If-Modified-Since"]; ok && len(lastStrs) > 0 {
		last, err := http.ParseTime(lastStrs[0])
		if *verbose && err != nil {
			log.Printf("could not parse If-Modified-Since: %v", err)
		}
		if !attrs.Updated.Truncate(time.Second).After(last) {
			w.WriteHeader(304)
			return
		}
	}

	gzipAcceptable := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	objr, err := client.Bucket(attrs.Bucket).Object(attrs.Name).ReadCompressed(gzipAcceptable).NewReader(r.Context())
	if err != nil {
		handleError(w, err)
		return
	}
	setTimeHeader(w, "Last-Modified", attrs.Updated)
	setStrHeader(w, "Content-Type", attrs.ContentType)
	setStrHeader(w, "Content-Language", attrs.ContentLanguage)
	setStrHeader(w, "Cache-Control", attrs.CacheControl)
	setStrHeader(w, "Content-Encoding", objr.Attrs.ContentEncoding)
	setStrHeader(w, "Content-Disposition", attrs.ContentDisposition)
	setIntHeader(w, "Content-Length", objr.Attrs.Size)
	io.Copy(w, objr)
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	setStrHeader(w, "Content-Type", "text/plain")
	io.WriteString(w, "OK\n")
}

func initAllowedBuckets() {
	b := *buckets
	if b == "" {
		b = os.Getenv("BUCKETS")
	}
	if b == "" {
		log.Fatal("BUCKETS environment variable is not set")
	}
	allowed_buckets = strings.Split(b, ",")
	log.Printf("Allowed buckets %+v", allowed_buckets)
}

func initBind() {
	b := *bind
	if b == "" {
		b = os.Getenv("BIND")
	}
	if b == "" {
		log.Printf("bind address is not passed. using default %s", default_bind)
		b = default_bind
	}
	*bind = b
}

func initDefaultRoot() {
	r := *defaultRoot
	if r == "" {
		r = os.Getenv("INDEX_FILE")
	}
	*defaultRoot = r
}

func main() {
	flag.Parse()

	// buckets can be passed as parameter or as environment variable
	initAllowedBuckets()
	initBind()
	initDefaultRoot()

	var err error
	if *credentials != "" {
		client, err = storage.NewClient(context.Background(), option.WithCredentialsFile(*credentials))
	} else {
		client, err = storage.NewClient(context.Background())
	}
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/_health", wrapper(healthCheck)).Methods("GET", "HEAD")
	r.HandleFunc("/{bucket:[0-9a-zA-Z-_.]+}/{object:.*}", wrapper(proxy)).Methods("GET", "HEAD")
	r.HandleFunc("/", wrapper(root)).Methods("GET", "HEAD")

	log.Printf("[service] listening on %s", *bind)
	if err := http.ListenAndServe(*bind, r); err != nil {
		log.Fatal(err)
	}
}
