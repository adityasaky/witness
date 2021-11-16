package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	witness "gitlab.com/testifysec/witness-cli/pkg"
	"gitlab.com/testifysec/witness-cli/pkg/crypto"
	"gitlab.com/testifysec/witness-cli/pkg/policy"
)

var attestationFilePaths []string

var verifyCmd = &cobra.Command{
	Use:           "verify [FILE]",
	Short:         "Verifies a witness layout",
	Long:          "Verifies a layout provided key source and exits with code 0 if verification succeeds",
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE:          runVerify,
	Args:          cobra.ExactArgs(1),
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.Flags().StringArrayVarP(&attestationFilePaths, "attestations", "a", []string{}, "Attestation files to test against the policy")
}

//todo: this logic should be broken out and moved to pkg/
//we need to abstract where keys are coming from, etc
func runVerify(cmd *cobra.Command, args []string) error {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		return fmt.Errorf("could not open key file: %v", err)
	}

	defer keyFile.Close()
	verifier, err := crypto.NewVerifierFromReader(keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	inFilePath := args[0]
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return fmt.Errorf("could not open file to sign: %v", err)
	}

	defer inFile.Close()
	policyEnvelope, err := witness.VerifySignature(inFile, verifier)
	if err != nil {
		return fmt.Errorf("could not verify policy: %v", err)
	}

	policy := policy.Policy{}
	err = json.Unmarshal(policyEnvelope.Payload, &policy)
	if err != nil {
		return fmt.Errorf("failed to parse policy: %v", err)
	}

	attestationFiles := []io.Reader{}
	for _, path := range attestationFilePaths {
		file, err := os.Open(path)
		if err != nil {
			return err
		}

		defer file.Close()
		attestationFiles = append(attestationFiles, file)
	}

	return policy.Verify(attestationFiles)
}
