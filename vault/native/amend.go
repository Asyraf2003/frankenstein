package main

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"time"

	"filippo.io/age"
)

// The Android onboarding adapter intentionally supports small credential vaults.
// Both encrypted input and expanded tar are bounded; larger vaults need the PC
// adapter rather than an unbounded in-memory rewrite on a phone.
const maxAmend = 16 << 20

// Input: uint32 JSON length, {"path":...,"base64":...}, then an FPE1 bundle.
// Authenticate the complete old archive before using any of its plaintext.
// Preserve local identity, kit_id, context and the independent recovery capsule.
func amend(source io.Reader) ([]byte, error) {
	var size uint32
	if binary.Read(source, binary.BigEndian, &size) != nil || size == 0 || size > maxManifest {
		return nil, invalid
	}
	request := make([]byte, size)
	if _, err := io.ReadFull(source, request); err != nil {
		return nil, invalid
	}
	input, err := object(request)
	if err != nil || !keys(input, "path", "base64") || text(input["path"]) != "credentials/github.json" {
		return nil, invalid
	}
	content, err := base64.StdEncoding.Strict().DecodeString(text(input["base64"]))
	if err != nil || len(content) == 0 || len(content) > 65536 {
		return nil, invalid
	}
	if _, err := object(content); err != nil {
		return nil, invalid
	}
	bundle, err := io.ReadAll(io.LimitReader(source, maxAmend+1))
	if err != nil || len(bundle) > maxAmend {
		return nil, invalid
	}
	proof, err := verify(bytes.NewReader(bundle), "")
	if err != nil {
		return nil, invalid
	}
	verified, err := object(proof)
	if err != nil {
		return nil, invalid
	}
	manifest := verified["manifest"].(map[string]any)
	headerSize := int(binary.BigEndian.Uint32(bundle[4:8]))
	header, err := object(bundle[8 : 8+headerSize])
	if err != nil {
		return nil, invalid
	}
	identities, err := age.ParseIdentities(strings.NewReader(text(header["identity"])))
	if err != nil {
		return nil, invalid
	}
	local := identities[0].(*age.X25519Identity)
	capsule := header["recovery"].(map[string]any)
	recipientBytes, err := base64.StdEncoding.Strict().DecodeString(text(capsule["recipient.txt"]))
	if err != nil {
		return nil, invalid
	}
	emergency, err := age.ParseX25519Recipient(strings.TrimSpace(string(recipientBytes)))
	if err != nil {
		return nil, invalid
	}
	decrypted, err := age.Decrypt(bytes.NewReader(bundle[8+headerSize:]), local)
	if err != nil {
		return nil, invalid
	}
	reader := tar.NewReader(decrypted)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for {
		member, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, invalid
		}
		if member.Name == "manifest.json" || member.Name == "payload/credentials/github.json" {
			continue
		}
		if member.Size > maxAmend-int64(archive.Len())-4096 {
			return nil, invalid
		}
		if err = writer.WriteHeader(&tar.Header{Name: member.Name, Mode: 0600, Size: member.Size, Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err = io.Copy(writer, reader); err != nil {
			return nil, err
		}
	}
	files := manifest["files"].(map[string]any)
	files["credentials/github.json"] = record{"credentials", int64(len(content)), sha(content)}
	manifest["created_at"] = time.Now().UTC().Format(time.RFC3339)
	metadata, err := json.Marshal(manifest)
	if err != nil || len(metadata) > maxManifest {
		return nil, invalid
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{"payload/credentials/github.json", content}, {"manifest.json", metadata}} {
		if archive.Len()+len(item.data)+4096 > maxAmend {
			return nil, invalid
		}
		if err = writer.WriteHeader(&tar.Header{Name: item.name, Mode: 0600, Size: int64(len(item.data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err = writer.Write(item.data); err != nil {
			return nil, err
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	encrypted, err := encrypt(archive.Bytes(), local.Recipient(), emergency)
	if err != nil {
		return nil, err
	}
	header["archive_sha256"] = sha(encrypted)
	encoded, err := json.Marshal(header)
	if err != nil || len(encoded) > 65536 {
		return nil, invalid
	}
	var output bytes.Buffer
	output.WriteString("FPE1")
	if err = binary.Write(&output, binary.BigEndian, uint32(len(encoded))); err != nil {
		return nil, err
	}
	output.Write(encoded)
	output.Write(encrypted)
	if output.Len() > maxAmend {
		return nil, invalid
	}
	if _, err = verify(bytes.NewReader(output.Bytes()), ""); err != nil {
		return nil, invalid
	}
	return output.Bytes(), nil
}
