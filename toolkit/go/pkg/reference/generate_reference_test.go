//go:build reference
// +build reference

package reference

import (
	"context"
	"os"
	"testing"

	"github.com/hyperledger/firefly-common/pkg/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestGenerateMarkdownPages(t *testing.T) {
	// TODO: Generate multiple languages when supported in the future here
	ctx := i18n.WithLang(context.Background(), language.AmericanEnglish)
	markdownMap, err := GenerateObjectsReferenceMarkdown(ctx)
	require.NoError(t, err)
	assert.NotNil(t, markdownMap)

	for pageName, markdown := range markdownMap {
		f, err := os.Create(pageName)
		assert.NoError(t, err)
		_, err = f.Write(markdown)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
	}
}
