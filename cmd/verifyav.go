// Copyright 2021-2024 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/in-toto/attestation-verifier/verifier"
	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/source"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

type VerifyAV struct {
	layoutPath    string
	archivistaURL string
	pipelineRun   string
}

func (vav *VerifyAV) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&vav.layoutPath,
		"layout",
		"",
		"path to ITE-10/11 layout (must be compatible with in-toto/attestation-verifier)",
	)
	cmd.MarkFlagRequired("layout") //nolint:errcheck

	cmd.Flags().StringVar(
		&vav.archivistaURL,
		"archivista",
		"https://archivista.testifysec.io",
		"URL of Archivista instance",
	)

	cmd.Flags().StringVar(
		&vav.pipelineRun,
		"pipeline-run",
		"",
		"pipeline run to be verified",
	)
	cmd.MarkFlagRequired("pipeline-run") //nolint:errcheck
}

func (vav *VerifyAV) Run(cmd *cobra.Command, args []string) error {
	layout, err := verifier.LoadLayout(vav.layoutPath)
	if err != nil {
		return err
	}

	stepNames := make([]string, 0, len(layout.Steps))
	for _, step := range layout.Steps {
		stepNames = append(stepNames, step.Name)
	}

	hash := sha256.Sum256([]byte(vav.pipelineRun))
	pipelineRunHash := hex.EncodeToString(hash[:])

	searcher := source.NewArchvistSource(archivista.New(vav.archivistaURL))
	envelopes := make([]source.CollectionEnvelope, 0, len(stepNames))
	for _, stepName := range stepNames {
		envelope, err := searcher.Search(cmd.Context(), stepName, []string{pipelineRunHash}, []string{"https://witness.dev/attestations/material/v0.1"})
		if err != nil {
			return err
		}

		if len(envelope) == 0 {
			return fmt.Errorf("attestation not found for step '%s' of '%s' in Archivista", stepName, vav.pipelineRun)
		}

		log.Infof("Found attestation for step '%s' of '%s' in Archivista", stepName, vav.pipelineRun)
		envelopes = append(envelopes, envelope...)
	}

	attestationsMap := make(map[string]*dsse.Envelope)
	for _, env := range envelopes {
		for _, signature := range env.Envelope.Signatures {
			newEnv := &dsse.Envelope{
				Payload:     base64.StdEncoding.EncodeToString(env.Envelope.Payload),
				PayloadType: env.Envelope.PayloadType,
				Signatures:  make([]dsse.Signature, 0, len(env.Envelope.Signatures)),
			}

			newEnv.Signatures = append(newEnv.Signatures, dsse.Signature{
				KeyID: signature.KeyID,
				Sig:   base64.StdEncoding.EncodeToString(signature.Signature),
			})
			attestationsMap[fmt.Sprintf("%s.%s", env.Collection.Name, signature.KeyID[:8])] = newEnv
		}
	}

	return verifier.Verify(layout, attestationsMap, nil)
}

func NewVerifyAVCmd() *cobra.Command {
	opts := &VerifyAV{}
	cmd := &cobra.Command{
		Use:               "verify-attestation-verifier",
		Short:             "Verifies an experimental in-toto policy (from ITE-10/11)",
		Long:              "Verifies an experimental in-toto policy and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE:              opts.Run,
	}
	opts.AddFlags(cmd)
	return cmd
}
