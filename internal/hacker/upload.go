package hacker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"path"
	"strings"

	"github.com/NICE-DEV226/nice-Scan/internal/transport"
	"github.com/NICE-DEV226/nice-Scan/internal/types"
)

// uploadMarker returns a unique, benign string to embed in a probe file and
// then look for on the server. Reading it back is the only honest basis for
// an "unrestricted upload" claim: a 200 on the POST proves nothing, because
// most endpoints answer 200 to any request.
func uploadMarker() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "nice-scan-upload-marker"
	}
	return "nicescan-marker-" + hex.EncodeToString(b[:])
}

// multipartFileBody builds a genuine multipart/form-data body carrying one
// file part (with its own part-level Content-Disposition/Content-Type) plus
// optional text fields. The previous upload code set a TOP-LEVEL
// Content-Disposition header on a raw body with no boundary and no multipart
// Content-Type — a spec-compliant server extracts no file from that, so the
// uploads silently never happened and every "accepted" verdict was noise.
// Returns the encoded body and the Content-Type header value (which carries
// the boundary) to send with it.
func multipartFileBody(field, filename, fileContentType, content string, fields map[string]string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf("form-data; name=%q; filename=%q", sanitizeFormParam(field), sanitizeFormParam(filename)))
	if fileContentType != "" {
		h.Set("Content-Type", fileContentType)
	}
	part, err := mw.CreatePart(h)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write([]byte(content)); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}

// sanitizeFormParam strips characters that would corrupt a Content-Disposition
// header (quotes, CR, LF). Test filenames never contain them, but a
// remote-influenced field name must not be able to break the multipart framing.
func sanitizeFormParam(s string) string {
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, "\\", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

// uploadProbeLocations lists same-origin URLs worth GET-ing for a file posted
// to pageURL under filename: the origin root, the posting page's own
// directory, and the conventional upload dirs. Kept short and same-origin so
// a marker probe never leaves the target.
func uploadProbeLocations(pageURL, filename string) []string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	dir := path.Dir(strings.TrimLeft(u.Path, "/"))
	if dir == "." || dir == "/" {
		dir = ""
	}
	cleanName := path.Base(filename)
	candidates := []string{
		base + "/" + cleanName,
		base + dir + "/" + cleanName,
		base + "/uploads/" + cleanName,
		base + "/files/" + cleanName,
		base + "/media/" + cleanName,
		base + "/static/uploads/" + cleanName,
		base + "/upload/" + cleanName,
	}
	seen := make(map[string]bool)
	var out []string
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// retrieveUploadMarker POSTs a benign marker file and, when the endpoint
// accepts it, probes the likely stored locations for one whose body contains
// the marker. Returns (storedURL, true) only when the marker comes back — the
// executed proof that the server both stored and served the upload.
func retrieveUploadMarker(ctx context.Context, client *transport.Client, pageURL, filename, fileContentType, marker string) (string, bool) {
	body, ctype, err := multipartFileBody("file", filename, fileContentType, marker, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(ctx, &types.Request{
		Method:  "POST",
		URL:     pageURL,
		Body:    body,
		Headers: map[string]string{"Content-Type": ctype},
	})
	if err != nil {
		return "", false
	}
	if !uploadAccepted(resp.StatusCode) {
		return "", false
	}
	for _, loc := range uploadProbeLocations(pageURL, filename) {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}
		vResp, err := client.Do(ctx, &types.Request{Method: "GET", URL: loc})
		if err != nil {
			continue
		}
		if strings.Contains(string(vResp.Body), marker) {
			return loc, true
		}
	}
	return "", false
}

func uploadAccepted(status int) bool {
	switch status {
	case 200, 201, 202, 204, 301, 302, 303, 307:
		return true
	default:
		return false
	}
}
