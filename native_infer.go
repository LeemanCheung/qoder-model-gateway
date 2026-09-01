package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	nativeInferPath  = "/algo/api/v2/service/pro/sse/agent_chat_generation"
	cosySignedPath   = "/api/v2/service/pro/sse/agent_chat_generation"
	nativeInferQuery = "?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"
)

type nativeInferHeaderValues struct {
	Authorization   string
	BusinessProduct string
	BusinessType    string
	ClientType      string
	DataPolicy      bool
	UnixSeconds     string
	Key             string
	MachineID       string
	OrganizationID  string
	Tags            []string
	Scene           string
	UID             string
	Version         string
	ModelKey        string
	ModelSource     string
}

type nativeInferAuthorizationPayload struct {
	Version     string `json:"version"`
	RequestID   string `json:"requestId"`
	Info        string `json:"info"`
	CosyVersion string `json:"cosyVersion"`
	IDEVersion  string `json:"ideVersion"`
}

func nativeInferURL(endpoint string) string {
	return endpoint + nativeInferPath + nativeInferQuery
}

func prepareNativeInferRequest(ctx context.Context, snapshot nativeContextSnapshot, input inferRequestInput) (*preparedRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	deps := protocolHostDepsFor(ctx, snapshot.host)
	if err := validateNativeInferPreparation(snapshot, input, deps); err != nil {
		return nil, err
	}
	encodedBody, err := snapshot.bodyCodec.Encode(input.Body)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now, err := deps.Clock.Now()
	if err != nil {
		if canceled := nativeInferCancellation(ctx, err); canceled != nil {
			return nil, canceled
		}
		if protocolErr := nativeInferExistingProtocolError(err); protocolErr != nil {
			return nil, protocolErr
		}
		return nil, newProtocolError(
			protocolBackendFailure,
			"Qoder protocol operation failed",
			fmt.Errorf("read native inference clock: %w", err),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var entropy [16]byte
	if err := deps.Entropy.Read(entropy[:]); err != nil {
		if canceled := nativeInferCancellation(ctx, err); canceled != nil {
			return nil, canceled
		}
		if protocolErr := nativeInferExistingProtocolError(err); protocolErr != nil {
			return nil, protocolErr
		}
		return nil, newProtocolError(
			protocolEntropyFailure,
			"Qoder protocol entropy is unavailable",
			fmt.Errorf("read native inference request entropy: %w", err),
		)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	requestID, err := nativeInferRequestID(entropy[:])
	if err != nil {
		return nil, err
	}
	unixSeconds := strconv.FormatInt(now.Unix(), 10)
	_, payloadB64, err := nativeInferPayload(requestID, snapshot.user.EncryptUserInfo, snapshot.version)
	if err != nil {
		return nil, err
	}
	signature := nativeInferSignature(payloadB64, snapshot.user.Key, unixSeconds, string(encodedBody))
	authorization := "Bearer COSY." + payloadB64 + "." + signature

	return &preparedRequest{
		URL: nativeInferURL(input.Endpoint),
		Header: nativeInferHeaders(nativeInferHeaderValues{
			Authorization:   authorization,
			BusinessProduct: snapshot.scene.BusinessProduct,
			BusinessType:    snapshot.scene.BusinessType,
			ClientType:      snapshot.scene.ClientType,
			DataPolicy:      snapshot.user.DataPolicyAgreed,
			UnixSeconds:     unixSeconds,
			Key:             snapshot.user.Key,
			MachineID:       snapshot.machineID,
			OrganizationID:  snapshot.user.OrganizationID,
			Tags:            snapshot.user.OrganizationTags,
			Scene:           snapshot.scene.Scene,
			UID:             snapshot.user.UID,
			Version:         snapshot.version,
			ModelKey:        input.ModelKey,
			ModelSource:     input.ModelSource,
		}),
		Body: encodedBody,
	}, nil
}

func validateNativeInferPreparation(snapshot nativeContextSnapshot, input inferRequestInput, deps protocolHostDeps) error {
	if snapshot.user.EncryptUserInfo == "" {
		return newProtocolError(protocolAuthUnavailable, "Qoder authentication is unavailable", errors.New("encrypted user information is empty"))
	}
	if snapshot.user.Key == "" {
		return newProtocolError(protocolAuthUnavailable, "Qoder authentication is unavailable", errors.New("runtime key is empty"))
	}
	if deps.Clock == nil || deps.Entropy == nil {
		return newProtocolError(protocolBackendFailure, "Qoder protocol operation failed", errors.New("native inference host dependencies are incomplete"))
	}
	return nil
}

func nativeInferExistingProtocolError(err error) error {
	var protocolErr *protocolError
	if errors.As(err, &protocolErr) {
		return err
	}
	return nil
}

func nativeInferCancellation(ctx context.Context, err error) error {
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func nativeInferRequestID(entropy []byte) (string, error) {
	if len(entropy) != 16 {
		return "", newProtocolError(
			protocolInvalidInput,
			"native inference input is invalid",
			errors.New("native infer request entropy length is invalid"),
		)
	}
	var raw [16]byte
	copy(raw[:], entropy)
	return formatLowerUUID(reverseMaskUUID(raw)), nil
}

func nativeInferHeaders(values nativeInferHeaderValues) http.Header {
	policy := "disagree"
	if values.DataPolicy {
		policy = "agree"
	}

	header := make(http.Header, 22)
	header.Set("Accept", "text/event-stream")
	header.Set("Authorization", values.Authorization)
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	header.Set("Content-Type", "application/json")
	header.Set("Cosy-Business-Product", values.BusinessProduct)
	header.Set("Cosy-Business-Type", values.BusinessType)
	header.Set("Cosy-ClientType", values.ClientType)
	header.Set("Cosy-Data-Policy", policy)
	header.Set("Cosy-Date", values.UnixSeconds)
	header.Set("Cosy-Key", values.Key)
	header.Set("Cosy-MachineId", values.MachineID)
	header.Set("Cosy-MachineToken", values.MachineID)
	header.Set("Cosy-MachineType", "5")
	if values.OrganizationID != "" {
		header.Set("Cosy-Organization-Id", values.OrganizationID)
	}
	if len(values.Tags) != 0 {
		header.Set("Cosy-Organization-Tags", strings.Join(values.Tags, ","))
	}
	header.Set("Cosy-Scene", values.Scene)
	header.Set("Cosy-User", values.UID)
	header.Set("Cosy-Version", values.Version)
	header.Set("Login-Version", "v2")
	if values.ModelKey != "" {
		header.Set("X-Model-Key", values.ModelKey)
		header.Set("X-Model-Source", values.ModelSource)
	}
	return header
}

func nativeInferSignature(payloadB64, key, unixSeconds, encodedBody string) string {
	sum := md5.Sum([]byte(payloadB64 + "\n" + key + "\n" + unixSeconds + "\n" + encodedBody + "\n" + cosySignedPath))
	return hex.EncodeToString(sum[:])
}

func nativeInferPayload(requestID, info, cosyVersion string) ([]byte, string, error) {
	raw, err := json.Marshal(nativeInferAuthorizationPayload{
		Version:     "v1",
		RequestID:   requestID,
		Info:        info,
		CosyVersion: cosyVersion,
		IDEVersion:  "",
	})
	if err != nil {
		return nil, "", err
	}
	return raw, base64.StdEncoding.EncodeToString(raw), nil
}
