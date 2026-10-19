package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriterWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriterWrapper) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

func (rw *responseWriterWrapper) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapper := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapper, r)

		reqID, _ := r.Context().Value(RequestIDKey).(string)
		// Solo r.URL.Path (sin query) y truncado: los secretos de gestion viajan en cabeceras, no en la URL.
		slog.Info("http request",
			"request_id", reqID, "method", r.Method, "path", trunc(r.URL.Path, 200),
			"status", wrapper.statusCode, "duration", time.Since(start).String(),
			"ip", GetRealIP(r.Context()), "bytes", wrapper.bytesWritten, "user_agent", trunc(r.UserAgent(), 200),
		)
	})
}
