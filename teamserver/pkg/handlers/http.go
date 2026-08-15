package handlers

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"Havoc/pkg/colors"
	"Havoc/pkg/common"
	"Havoc/pkg/common/certs"
	"Havoc/pkg/logger"
	"Havoc/pkg/logr"

	"github.com/gin-gonic/gin"
)

//go:embed 404.html
var fake404Page []byte

func NewConfigHttp() *HTTP {
	var config = new(HTTP)

	config.GinEngine = gin.New()

	return config
}

func (h *HTTP) generateCertFiles() bool {

	var (
		err          error
		ListenerName string
		ListenerPath string
	)

	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		log.Fatal(err)
	}

	ListenerName = reg.ReplaceAllString(h.Config.Name, "")
	ListenerPath = logr.LogrInstance.ListenerPath + "/" + ListenerName + "/"

	logger.Debug("Listener Path:", ListenerPath)

	if _, err := os.Stat(ListenerPath); os.IsNotExist(err) {
		if err = os.Mkdir(ListenerPath, os.ModePerm); err != nil {
			logger.Error("Failed to create Logr listener " + h.Config.Name + " folder: " + err.Error())
			return false
		}
	}

	h.TLS.CertPath = ListenerPath + "server.crt"
	h.TLS.KeyPath = ListenerPath + "server.key"

	h.TLS.Cert, h.TLS.Key, err = certs.HTTPSGenerateRSACertificate(common.GetInterfaceIpv4Addr(h.Config.HostBind))

	err = os.WriteFile(h.TLS.CertPath, h.TLS.Cert, 0644)
	if err != nil {
		logger.Error("Couldn't save server cert file: " + err.Error())
		return false
	}

	err = os.WriteFile(h.TLS.KeyPath, h.TLS.Key, 0600)
	if err != nil {
		logger.Error("Couldn't save server key file: " + err.Error())
		return false
	}

	logger.Debug("Successful generated tls certifications")

	return true
}

// fake nginx 404 page
func (h *HTTP) fake404(ctx *gin.Context) {
	ctx.Writer.WriteHeader(http.StatusNotFound)
	ctx.Header("Server", "nginx")
	ctx.Header("Content-Type", "text/html")
	ctx.Writer.Write(fake404Page)
}

func (h *HTTP) extractMetadata(ctx *gin.Context) ([]byte, error) {
	loc := strings.ToLower(h.Config.DataLocation.Location)
	name := h.Config.DataLocation.Name

	switch loc {
	case "header":
		encoded := ctx.Request.Header.Get(name)
		if encoded == "" {
			return nil, fmt.Errorf("metadata header %s is empty", name)
		}
		return base64.StdEncoding.DecodeString(encoded)

	case "cookie":
		cookie, err := ctx.Request.Cookie(name)
		if err != nil || cookie == nil {
			return nil, fmt.Errorf("metadata cookie %s not found", name)
		}
		return base64.StdEncoding.DecodeString(cookie.Value)

	case "parameter":
		encoded := ctx.Query(name)
		if encoded == "" {
			return nil, fmt.Errorf("metadata parameter %s is empty", name)
		}
		return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encoded)

	default:
		return nil, nil
	}
}

func (h *HTTP) writeResponse(ctx *gin.Context, data []byte) {
	for _, Header := range h.Config.Response.Headers {
		var hdr = strings.Split(Header, ":")
		if len(hdr) > 1 {
			ctx.Header(hdr[0], strings.TrimSpace(hdr[1]))
		}
	}

	respLoc := strings.ToLower(h.Config.Response.DataLocation.Location)
	respName := h.Config.Response.DataLocation.Name

	if respLoc == "" || respLoc == "body" || len(data) <= 12 {
		ctx.Writer.Write(data)
		return
	}

	metadata := data[:12]
	bulk := data[12:]
	encoded := base64.StdEncoding.EncodeToString(metadata)

	switch respLoc {
	case "header":
		ctx.Header(respName, encoded)
	case "cookie":
		http.SetCookie(ctx.Writer, &http.Cookie{
			Name:  respName,
			Value: encoded,
			Path:  "/",
		})
	case "parameter":
		ctx.Header(respName, encoded)
	}

	ctx.Writer.Write(bulk)
}

func (h *HTTP) request(ctx *gin.Context) {
	var ExternalIP string
	var MissingHdr string

	Body, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		logger.Debug("Error while reading request: " + err.Error())
	}

	if h.Config.BehindRedir {
		ExternalIP = ctx.Request.Header.Get("X-Forwarded-For")
	} else {
		ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]
	}

	// extract metadata from configured location and reconstruct payload
	metadataBytes, err := h.extractMetadata(ctx)
	if err != nil {
		logger.Warn("Failed to extract metadata: " + err.Error())
		// dump all request headers for debugging
		var hdrs string
		for name, values := range ctx.Request.Header {
			for _, v := range values {
				hdrs += fmt.Sprintf("  %s: %s\n", name, v)
			}
		}
		logger.Debug(fmt.Sprintf("Request headers received:\n%sMethod: %s, URI: %s, Body length: %d",
			hdrs, ctx.Request.Method, ctx.Request.URL.Path, len(Body)))
		h.fake404(ctx)
		return
	}

	var FullPayload []byte
	if metadataBytes != nil && len(metadataBytes) >= 12 {
		FullPayload = append(metadataBytes, Body...)
	} else {
		FullPayload = Body
	}

	// check that the headers defined on the profile are present
	valid := true
	IgnoreHeaders := [2]string{"Connection", "Accept-Encoding"}
	for _, Header := range h.Config.Headers {
		NameValue := strings.Split(Header, ": ")
		if len(NameValue) > 1 {
			ignore := false
			for _, IgnoreHeader := range IgnoreHeaders {
				if strings.ToLower(NameValue[0]) == strings.ToLower(IgnoreHeader) {
					ignore = true
					break
				}
			}
			if ignore == false {
				if strings.ToLower(ctx.Request.Header.Get(NameValue[0])) != strings.ToLower(NameValue[1]) {
					MissingHdr = NameValue[0] + ": " + ctx.Request.Header.Get(NameValue[0])
					valid = false
					break
				}
			}
		}
	}

	if len(h.Config.HostHeader) > 0 {
		if strings.ToLower(ctx.Request.Host) == strings.ToLower(h.Config.HostHeader) {
			valid = true
		} else if strings.ToLower(ctx.Request.Header.Get("X-Forwarded-Host")) == strings.ToLower(h.Config.HostHeader) {
			valid = true
		} else {
			MissingHdr = "Host: " + ctx.Request.Host + "; X-Forwarded-Host: " + ctx.Request.Header.Get("X-Forwarded-Host")
			valid = false
		}
	}

	if valid == false {
		logger.Warn(fmt.Sprintf("got a request with an invalid header: %s", MissingHdr))
		h.fake404(ctx)
		return
	}

	// strip UriPrefix so redirected paths match base URIs
	requestPath := ctx.Request.URL.Path
	if h.Config.UriPrefix != "" {
		requestPath = strings.TrimPrefix(requestPath, h.Config.UriPrefix)
	}

	// check that the URI path matches (use URL.Path to ignore query params)
	if len(h.Config.Uris) > 0 && !(len(h.Config.Uris) == 1 && h.Config.Uris[0] == "") {
		valid = false
		for _, Uri := range h.Config.Uris {
			if requestPath == Uri {
				valid = true
				break
			}
		}

		if valid == false {
			logger.Warn(fmt.Sprintf("got a request with an invalid request path: %s", ctx.Request.URL.Path))
			h.fake404(ctx)
			return
		}
	}

	// check that the User-Agent is valid
	if h.Config.UserAgent != "" {
		if h.Config.UserAgent != ctx.Request.UserAgent() {
			logger.Warn(fmt.Sprintf("got a request with an invalid user agent: %s", ctx.Request.UserAgent()))
			h.fake404(ctx)
			return
		}
	}

	logger.Debug(fmt.Sprintf("FullPayload length: %d, Body length: %d, metadata length: %d", len(FullPayload), len(Body), len(metadataBytes)))

	if Response, Success := parseAgentRequest(h.Teamserver, FullPayload, ExternalIP, h.Config.MagicValue); Success {
		h.writeResponse(ctx, Response.Bytes())
	} else {
		logger.Warn("failed to parse agent request")
		h.fake404(ctx)
		return
	}

	ctx.AbortWithStatus(http.StatusOK)
	return
}

func (h *HTTP) Start() {
	logger.Debug("Setup HTTP/s Server")

	if len(h.Config.Hosts) == 0 && h.Config.PortBind == "" && h.Config.Name == "" {
		logger.Error("HTTP Hosts/Port/Name not set")
		return
	}

	h.GinEngine.POST("/*endpoint", h.request)
	loc := strings.ToLower(h.Config.DataLocation.Location)
	if loc != "" && loc != "body" {
		h.GinEngine.GET("/*endpoint", h.request)
	} else {
		h.GinEngine.GET("/*endpoint", h.fake404)
	}
	h.Active = true

	if h.Config.Secure && !h.Config.BehindRedir {
		// TODO: only generate certs if h.Config.Cert is empty
		if h.generateCertFiles() {
			logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("https://"+common.GetInterfaceIpv4Addr(h.Config.HostBind)+":"+h.Config.PortBind))

			pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
			h.Teamserver.EventAppend(pk)
			h.Teamserver.EventBroadcast("", pk)

			go func() {
				var (
					CertPath = h.TLS.CertPath
					KeyPath  = h.TLS.KeyPath
				)

				h.Server = &http.Server{
					Addr:    common.GetInterfaceIpv4Addr(h.Config.HostBind) + ":" + h.Config.PortBind,
					Handler: h.GinEngine,
				}

				if h.Config.Cert.Cert != "" && h.Config.Cert.Key != "" {
					CertPath = h.Config.Cert.Cert
					KeyPath = h.Config.Cert.Key
				}

				err := h.Server.ListenAndServeTLS(CertPath, KeyPath)
				if err != nil {
					if err == http.ErrServerClosed {
						h.Active = false
					} else {
						logger.Error("Couldn't start HTTPs handler: " + err.Error())
						h.Active = false
						h.Teamserver.EventListenerError(h.Config.Name, err)
					}
				}
			}()
		} else {
			logger.Error("Failed to generate server tls certifications")
		}
	} else {
		logger.Info("Started \"" + colors.Green(h.Config.Name) + "\" listener: " + colors.BlueUnderline("http://"+common.GetInterfaceIpv4Addr(h.Config.HostBind)+":"+h.Config.PortBind))

		pk := h.Teamserver.ListenerAdd("", LISTENER_HTTP, h)
		h.Teamserver.EventAppend(pk)
		h.Teamserver.EventBroadcast("", pk)

		go func() {
			h.Server = &http.Server{
				Addr:    common.GetInterfaceIpv4Addr(h.Config.HostBind) + ":" + h.Config.PortBind,
				Handler: h.GinEngine,
			}

			err := h.Server.ListenAndServe()
			if err != nil {
				logger.Error("Couldn't start HTTP handler: " + err.Error())
				h.Active = false
				h.Teamserver.EventListenerError(h.Config.Name, err)
			}
		}()
	}
}

func (h *HTTP) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Server.Shutdown(ctx); err != nil {
		return err
	}
	// catching ctx.Done(). timeout of 5 seconds.
	select {
	case <-ctx.Done():
		logger.Debug("timeout of 5 seconds.")
	}

	return nil
}
