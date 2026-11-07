package main

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

// Enrollment is deliberately bounded to small profile/credential inputs.
// Later media/project sync belongs to the streaming owner adapters.
const maxEnrollment = 2 << 20

func encrypt(content []byte, recipients ...age.Recipient) ([]byte, error) {
	var output bytes.Buffer
	writer, err := age.Encrypt(&output, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err = writer.Write(content); err != nil {
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func enroll(source io.Reader) ([]byte, error) {
	request, err := io.ReadAll(io.LimitReader(source, maxEnrollment+1))
	if err != nil || len(request) > maxEnrollment {
		return nil, invalid
	}
	input, err := object(request)
	if err != nil || !keys(input, "context", "files", "recovery_passphrase") {
		return nil, invalid
	}
	ctx, err := context(input["context"])
	if err != nil {
		return nil, invalid
	}
	phrase, phraseOK := input["recovery_passphrase"].(string)
	if !phraseOK || (phrase != "" && utf8.RuneCountInString(phrase) < 20) || len(phrase) > 4096 || strings.ContainsAny(phrase, "\x00\r\n") {
		return nil, invalid
	}
	files, ok := input["files"].(map[string]any)
	if !ok || len(files) == 0 || len(files) > 128 {
		return nil, invalid
	}
	decoded := map[string][]byte{}
	records := map[string]record{}
	present := map[string]bool{}
	names := []string{}
	for name, value := range files {
		parts := strings.Split(name, "/")
		if len(parts) < 2 || !owners[parts[0]] || path.Clean(name) != name || strings.ContainsAny(name, "\x00\r\n\\") {
			return nil, invalid
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				return nil, invalid
			}
		}
		encoded, ok := value.(string)
		if !ok {
			return nil, invalid
		}
		content, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(content) > maxManifest {
			return nil, invalid
		}
		decoded[name] = content
		records[name] = record{parts[0], int64(len(content)), sha(content)}
		present[parts[0]] = true
		names = append(names, name)
	}
	for _, owner := range ctx["required_owners"].([]string) {
		if !present[owner] {
			return nil, invalid
		}
	}
	sort.Strings(names)
	local, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	recipients := []age.Recipient{local.Recipient()}
	var capsule any
	var capsuleDigest any
	schema := 2 // Explicit device-key-only mode, never an invented recovery secret.
	if phrase != "" {
		emergency, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		password, err := age.NewScryptRecipient(phrase)
		if err != nil {
			return nil, err
		}
		// Keep age's standard scrypt work factor; never invent a password KDF.
		wrapped, err := encrypt([]byte(emergency.String()+"\n"), password)
		if err != nil {
			return nil, err
		}
		recipient := []byte(emergency.Recipient().String() + "\n")
		capsuleManifest, err := json.Marshal(map[string]any{"schema": 1, "purpose": "outer-kit-opening-v1",
			"recipient": emergency.Recipient().String(), "identity_sha256": sha(wrapped), "recipient_sha256": sha(recipient)})
		if err != nil {
			return nil, err
		}
		entries := map[string]string{}
		for name, content := range map[string][]byte{"identity.age": wrapped, "recipient.txt": recipient, "manifest.json": capsuleManifest} {
			entries[name] = base64.StdEncoding.EncodeToString(content)
		}
		capsule = entries
		capsuleDigest = sha(capsuleManifest)
		schema = 1
		recipients = append(recipients, emergency.Recipient())
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(map[string]any{"schema": 1, "kit_id": hex.EncodeToString(random[:]),
		"created_at": time.Now().UTC().Format(time.RFC3339), "context": ctx, "files": records})
	if err != nil {
		return nil, err
	}
	var archive bytes.Buffer
	tarWriter := tar.NewWriter(&archive)
	add := func(name string, content []byte) error {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tarWriter.Write(content)
		return err
	}
	for _, name := range names {
		if err := add("payload/"+name, decoded[name]); err != nil {
			return nil, err
		}
	}
	if err := add("manifest.json", manifest); err != nil {
		return nil, err
	}
	if err := tarWriter.Close(); err != nil {
		return nil, err
	}
	encrypted, err := encrypt(archive.Bytes(), recipients...)
	if err != nil {
		return nil, err
	}
	header, err := json.Marshal(map[string]any{"schema": schema, "identity": local.String() + "\n", "context": ctx,
		"archive_sha256": sha(encrypted), "recovery_manifest_sha256": capsuleDigest, "recovery": capsule})
	if err != nil || len(header) > 65536 {
		return nil, invalid
	}
	var bundle bytes.Buffer
	bundle.WriteString("FPE1")
	if err := binary.Write(&bundle, binary.BigEndian, uint32(len(header))); err != nil {
		return nil, err
	}
	bundle.Write(header)
	bundle.Write(encrypted)
	// Exercise the exact consumer before making a candidate visible to Android.
	if _, err := verify(bytes.NewReader(bundle.Bytes()), ""); err != nil {
		return nil, err
	}
	return bundle.Bytes(), nil
}
