package parser

import (
    "bytes"
    "log/slog"
    "strings"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func newTestParser() *Parser {
    logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
    return New(logger)
}

func TestParseBasicClasses(t *testing.T) {
    input := `
+webserver
+database
-deprecated_class
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    classes := p.GetClasses()
    assert.Equal(t, ClassActive, classes["webserver"])
    assert.Equal(t, ClassActive, classes["database"])
    assert.Equal(t, ClassCancelled, classes["deprecated_class"])
}

func TestParseVariables(t *testing.T) {
    input := `
=hostname=web01.example.com
@roles=web,app,cache
%config=key:value
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    vars := p.GetVariables()
    assert.Equal(t, "=hostname=web01.example.com", vars["hostname"])
    assert.Equal(t, "@roles=web,app,cache", vars["roles"])
    assert.Equal(t, "%config=key:value", vars["config"])
}

func TestResetCommands(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected map[string]ClassState
    }{
        {
            name: "reset all classes",
            input: `
+class1
+class2
!RESET_ALL_CLASSES
+class3
            `,
            expected: map[string]ClassState{
                "class3": ClassActive,
            },
        },
        {
            name: "reset active classes",
            input: `
+active1
-cancelled1
+active2
!RESET_ACTIVE_CLASSES
-cancelled2
            `,
            expected: map[string]ClassState{
                "cancelled1": ClassCancelled,
                "cancelled2": ClassCancelled,
            },
        },
        {
            name: "reset cancelled classes",
            input: `
+active1
-cancelled1
-cancelled2
!RESET_CANCELLED_CLASSES
+active2
            `,
            expected: map[string]ClassState{
                "active1": ClassActive,
                "active2": ClassActive,
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            p := newTestParser()
            err := p.Parse(strings.NewReader(tt.input), "test")
            require.NoError(t, err)

            classes := p.GetClasses()
            assert.Equal(t, tt.expected, classes)
        })
    }
}

func TestResetVariable(t *testing.T) {
    input := `
=var1=value1
=var2=value2
/var1
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    vars := p.GetVariables()
    assert.NotContains(t, vars, "var1")
    assert.Contains(t, vars, "var2")
}

func TestResetClass(t *testing.T) {
    input := `
+class1
+class2
_class1
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    classes := p.GetClasses()
    assert.NotContains(t, classes, "class1")
    assert.Contains(t, classes, "class2")
}

func TestLastVariableWins(t *testing.T) {
    input := `
=var=first
=var=second
=var=third
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    vars := p.GetVariables()
    assert.Equal(t, "=var=third", vars["var"])
}

func TestMultipleFiles(t *testing.T) {
    file1 := `
+class1
=var1=value1
    `
    file2 := `
+class2
=var2=value2
    `

    p := newTestParser()
    require.NoError(t, p.Parse(strings.NewReader(file1), "file1"))
    require.NoError(t, p.Parse(strings.NewReader(file2), "file2"))

    classes := p.GetClasses()
    assert.Equal(t, ClassActive, classes["class1"])
    assert.Equal(t, ClassActive, classes["class2"])

    vars := p.GetVariables()
    assert.Contains(t, vars, "var1")
    assert.Contains(t, vars, "var2")
}

func TestPrintOutput(t *testing.T) {
    input := `
+webserver
-oldclass
=hostname=server01
    `

    p := newTestParser()
    require.NoError(t, p.Parse(strings.NewReader(input), "test"))

    var buf bytes.Buffer
    require.NoError(t, p.Print(&buf))

    output := buf.String()
    assert.Contains(t, output, "+henc_classification_completed")
    assert.Contains(t, output, "+webserver")
    assert.Contains(t, output, "-oldclass")
    assert.Contains(t, output, "=hostname=server01")
}

func TestIgnoreComments(t *testing.T) {
    input := `
# This is a comment
+class1
# Another comment
=var=value
    `

    p := newTestParser()
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    classes := p.GetClasses()
    assert.Len(t, classes, 1)
    assert.Equal(t, ClassActive, classes["class1"])
}

func TestInvalidSyntax(t *testing.T) {
    input := `
+valid_class
this is invalid
=valid_var=value
    `

    p := newTestParser()
    // Should not return error, just skip invalid lines
    err := p.Parse(strings.NewReader(input), "test")
    require.NoError(t, err)

    classes := p.GetClasses()
    assert.Contains(t, classes, "valid_class")
}
