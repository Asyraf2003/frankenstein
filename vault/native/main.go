// Native Android age adapter. Cryptography is owned by filippo.io/age.
// Input: FPE1 portable bundle on stdin. No secrets in arguments or diagnostics.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
)

const maxArchive = 8 << 30
const maxManifest = 1 << 20

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var owners = map[string]bool{"credentials": true, "recovery": true, "keyring": true, "vault": true, "projects": true, "desired": true}
var invalid = errors.New("portable vault verification failed")

// encoding/json normally accepts duplicate object keys. Reject them at every
// level so Python and Android cannot assign different meanings to the same data.
func jsonValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, invalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		result := map[string]any{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, invalid
			}
			if _, exists := result[name]; exists {
				return nil, invalid
			}
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result[name] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, invalid
		}
		return result, nil
	case json.Delim('['):
		result := []any{}
		for decoder.More() {
			value, err := jsonValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, invalid
		}
		return result, nil
	default:
		if _, delimiter := token.(json.Delim); delimiter {
			return nil, invalid
		}
		return token, nil
	}
}

func object(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := jsonValue(decoder, 0)
	result, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	return result, nil
}

func keys(value map[string]any, expected ...string) bool {
	if len(value) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}
func text(value any) string  { result, _ := value.(string); return result }
func sha(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func context(value any) (map[string]any, error) {
	ctx, ok := value.(map[string]any)
	if !ok || !keys(ctx, "revisions", "features", "required_owners") {
		return nil, invalid
	}
	revisions, ok := ctx["revisions"].(map[string]any)
	if !ok || !keys(revisions, "engine", "state") {
		return nil, invalid
	}
	for _, revision := range revisions {
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(text(revision)) {
			return nil, invalid
		}
	}
	for _, field := range []string{"features", "required_owners"} {
		values, ok := ctx[field].([]any)
		if !ok || (field == "required_owners" && len(values) == 0) {
			return nil, invalid
		}
		seen := map[string]bool{}
		normalized := []string{}
		for _, item := range values {
			s := text(item)
			if s == "" || utf8.RuneCountInString(s) > 128 || seen[s] || (field == "required_owners" && !owners[s]) {
				return nil, invalid
			}
			seen[s] = true
			normalized = append(normalized, s)
		}
		sort.Strings(normalized)
		ctx[field] = normalized
	}
	return ctx, nil
}

func recovery(header map[string]any) error {
	if header["schema"] == json.Number("2") {
		if header["recovery"] == nil && header["recovery_manifest_sha256"] == nil {
			return nil
		}
		return invalid
	}
	entries, ok := header["recovery"].(map[string]any)
	if !ok || !keys(entries, "identity.age", "recipient.txt", "manifest.json") {
		return invalid
	}
	decoded := map[string][]byte{}
	for name, value := range entries {
		data, err := base64.StdEncoding.Strict().DecodeString(text(value))
		if err != nil || len(data) == 0 || len(data) > 65536 {
			return invalid
		}
		decoded[name] = data
	}
	if sha(decoded["manifest.json"]) != text(header["recovery_manifest_sha256"]) {
		return invalid
	}
	manifest, err := object(decoded["manifest.json"])
	if err != nil || !keys(manifest, "schema", "purpose", "recipient", "identity_sha256", "recipient_sha256") {
		return invalid
	}
	if manifest["schema"] != json.Number("1") || text(manifest["purpose"]) != "outer-kit-opening-v1" {
		return invalid
	}
	recipient := text(manifest["recipient"])
	if _, err := age.ParseX25519Recipient(recipient); err != nil {
		return invalid
	}
	if string(decoded["recipient.txt"]) != recipient+"\n" || sha(decoded["recipient.txt"]) != text(manifest["recipient_sha256"]) || sha(decoded["identity.age"]) != text(manifest["identity_sha256"]) {
		return invalid
	}
	if !bytes.HasPrefix(decoded["identity.age"], []byte("age-encryption.org/v1\n-> scrypt ")) {
		return invalid
	}
	return nil
}

type record struct {
	Owner  string `json:"owner"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func verify(source io.Reader, selected string) ([]byte, error) {
	// Entire parser is bounded and streaming, even for multi-gigabyte archives.
	bounded := &io.LimitedReader{R: source, N: maxArchive + 1}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(bounded, prefix); err != nil || string(prefix[:4]) != "FPE1" {
		return nil, invalid
	}
	size := binary.BigEndian.Uint32(prefix[4:])
	if size == 0 || size > 65536 {
		return nil, invalid
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(bounded, data); err != nil {
		return nil, invalid
	}
	header, err := object(data)
	if err != nil || !keys(header, "schema", "identity", "context", "archive_sha256", "recovery_manifest_sha256", "recovery") || (header["schema"] != json.Number("1") && header["schema"] != json.Number("2")) {
		return nil, invalid
	}
	expected, err := context(header["context"])
	if err != nil || !digestPattern.MatchString(text(header["archive_sha256"])) || recovery(header) != nil {
		return nil, invalid
	}
	identity := text(header["identity"])
	if len(identity) == 0 || len(identity) > 4096 {
		return nil, invalid
	}
	identities, err := age.ParseIdentities(strings.NewReader(identity))
	if err != nil || len(identities) != 1 {
		return nil, invalid
	}
	if _, ok := identities[0].(*age.X25519Identity); !ok {
		return nil, invalid
	}
	cipherDigest := sha256.New()
	decrypted, err := age.Decrypt(io.TeeReader(bounded, cipherDigest), identities...)
	if err != nil {
		return nil, invalid
	}
	archive := tar.NewReader(decrypted)
	actual := map[string]record{}
	var manifest map[string]any
	var selectedBytes []byte
	selectedFound := selected == ""
	for {
		member, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil || (member.Typeflag != tar.TypeReg && member.Typeflag != tar.TypeRegA) || member.Size < 0 || member.Size > maxArchive {
			return nil, invalid
		}
		name := member.Name
		if name == "manifest.json" {
			if manifest != nil || member.Size > maxManifest {
				return nil, invalid
			}
			content, err := io.ReadAll(archive)
			if err != nil {
				return nil, invalid
			}
			manifest, err = object(content)
			if err != nil {
				return nil, invalid
			}
			continue
		}
		if !strings.HasPrefix(name, "payload/") {
			return nil, invalid
		}
		name = strings.TrimPrefix(name, "payload/")
		parts := strings.Split(name, "/")
		if len(parts) < 2 || !owners[parts[0]] || path.Clean(name) != name || strings.ContainsAny(name, "\x00\r\n\\") {
			return nil, invalid
		}
		for _, part := range parts {
			if part == ".." || part == "." || part == "" {
				return nil, invalid
			}
		}
		if _, duplicate := actual[name]; duplicate || len(actual) >= 10000 {
			return nil, invalid
		}
		hash := sha256.New()
		var writer io.Writer = hash
		var content bytes.Buffer
		if name == selected {
			if member.Size > maxManifest {
				return nil, invalid
			}
			writer = io.MultiWriter(hash, &content)
			selectedFound = true
		}
		count, err := io.Copy(writer, archive)
		if err != nil || count != member.Size {
			return nil, invalid
		}
		actual[name] = record{parts[0], count, hex.EncodeToString(hash.Sum(nil))}
		if name == selected {
			selectedBytes = content.Bytes()
		}
	}
	// tar EOF is not age EOF. Authenticate the final age chunk before emitting
	// even a single byte of manifest or selected plaintext to the caller.
	tail, err := io.ReadAll(io.LimitReader(decrypted, 10241))
	if err != nil || len(tail) > 10240 || bytes.Count(tail, []byte{0}) != len(tail) {
		return nil, invalid
	}
	var probe [1]byte
	if n, err := decrypted.Read(probe[:]); n != 0 || err != io.EOF {
		return nil, invalid
	}
	if bounded.N <= 0 || hex.EncodeToString(cipherDigest.Sum(nil)) != text(header["archive_sha256"]) || !selectedFound {
		return nil, invalid
	}
	if !keys(manifest, "schema", "kit_id", "created_at", "context", "files") || manifest["schema"] != json.Number("1") ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(text(manifest["kit_id"])) || text(manifest["created_at"]) == "" {
		return nil, invalid
	}
	observed, err := context(manifest["context"])
	if err != nil || !reflect.DeepEqual(expected, observed) {
		return nil, invalid
	}
	files, ok := manifest["files"].(map[string]any)
	if !ok || len(files) == 0 || len(files) != len(actual) {
		return nil, invalid
	}
	present := map[string]bool{}
	for name, entry := range actual {
		value, ok := files[name].(map[string]any)
		if !ok || !keys(value, "owner", "size", "sha256") || text(value["owner"]) != entry.Owner || text(value["sha256"]) != entry.SHA256 || value["size"] != json.Number(fmt.Sprint(entry.Size)) {
			return nil, invalid
		}
		present[entry.Owner] = true
	}
	for _, owner := range observed["required_owners"].([]string) {
		if !present[owner] {
			return nil, invalid
		}
	}
	result := map[string]any{"manifest": manifest}
	if selected != "" {
		result["selected"] = map[string]string{"path": selected, "base64": base64.StdEncoding.EncodeToString(selectedBytes)}
	}
	return json.Marshal(result)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "amend-github" {
		result, err := amend(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "VAULT_AMENDMENT_FAILED")
			os.Exit(1)
		}
		os.Stdout.Write(result)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "enroll" {
		result, err := enroll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "VAULT_ENROLLMENT_FAILED")
			os.Exit(1)
		}
		os.Stdout.Write(result)
		return
	}
	selected := ""
	if len(os.Args) == 3 && os.Args[1] == "read" {
		selected = os.Args[2]
	} else if len(os.Args) != 2 || os.Args[1] != "verify" {
		os.Exit(2)
	}
	result, err := verify(os.Stdin, selected)
	if err != nil {
		// Do not expose parse errors containing private input bytes.
		fmt.Fprintln(os.Stderr, "VAULT_VERIFICATION_FAILED")
		os.Exit(1)
	}
	os.Stdout.Write(result)
}
