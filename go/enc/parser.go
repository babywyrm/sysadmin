package parser

import (
    "bufio"
    "fmt"
    "io"
    "log/slog"
    "os"
    "regexp"
    "strings"
)

var (
    // Match ENC setting lines: optional whitespace, operator, value
    settingRe = regexp.MustCompile(`^\s*([=@%+\-/_!])(.+)\s*$`)
    
    // Match variable name in assignments (everything before =)
    varRe = regexp.MustCompile(`^(.+?)=`)
)

// Parser processes ENC files and maintains state
type Parser struct {
    classes   map[string]ClassState
    variables map[string]string
    logger    *slog.Logger
}

// New creates a new ENC parser
func New(logger *slog.Logger) *Parser {
    return &Parser{
        classes:   make(map[string]ClassState),
        variables: make(map[string]string),
        logger:    logger,
    }
}

// ParseFile reads and processes an ENC file
func (p *Parser) ParseFile(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("open file: %w", err)
    }
    defer file.Close()

    return p.Parse(file, filename)
}

// Parse processes ENC directives from a reader
func (p *Parser) Parse(r io.Reader, source string) error {
    scanner := bufio.NewScanner(r)
    lineNum := 0

    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())

        // Skip empty lines and comments
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        setting, err := p.parseLine(line, lineNum)
        if err != nil {
            p.logger.Warn("invalid line",
                "source", source,
                "line", lineNum,
                "content", line,
                "error", err)
            continue
        }

        if err := p.processSetting(setting); err != nil {
            p.logger.Warn("failed to process setting",
                "source", source,
                "setting", setting,
                "error", err)
        }
    }

    if err := scanner.Err(); err != nil {
        return fmt.Errorf("scan %s: %w", source, err)
    }

    return nil
}

// parseLine extracts a setting from a line
func (p *Parser) parseLine(line string, lineNum int) (*Setting, error) {
    matches := settingRe.FindStringSubmatch(line)
    if matches == nil {
        return nil, fmt.Errorf("invalid syntax")
    }

    return &Setting{
        Type:  SettingType(matches[1][0]),
        Value: strings.TrimSpace(matches[2]),
        Line:  lineNum,
    }, nil
}

// processSetting applies a setting to the parser state
func (p *Parser) processSetting(s *Setting) error {
    switch s.Type {
    case SettingCommand:
        return p.executeCommand(Command(s.Value))
    
    case SettingAddClass:
        p.classes[s.Value] = ClassActive
        p.logger.Debug("added class", "name", s.Value)
    
    case SettingDelClass:
        p.classes[s.Value] = ClassCancelled
        p.logger.Debug("cancelled class", "name", s.Value)
    
    case SettingResetClass:
        delete(p.classes, s.Value)
        p.logger.Debug("reset class", "name", s.Value)
    
    case SettingVariable, SettingArray, SettingHash:
        varName := p.extractVarName(s.Value)
        if varName == "" {
            return fmt.Errorf("invalid variable assignment")
        }
        // Store the full line (including the prefix)
        p.variables[varName] = fmt.Sprintf("%c%s", s.Type, s.Value)
        p.logger.Debug("set variable",
            "name", varName,
            "type", string(s.Type))
    
    case SettingResetVar:
        delete(p.variables, s.Value)
        p.logger.Debug("reset variable", "name", s.Value)
    
    default:
        return fmt.Errorf("unknown setting type: %c", s.Type)
    }

    return nil
}

// extractVarName extracts the variable name from an assignment
func (p *Parser) extractVarName(assignment string) string {
    matches := varRe.FindStringSubmatch(assignment)
    if matches == nil {
        return ""
    }
    return matches[1]
}

// executeCommand handles special commands
func (p *Parser) executeCommand(cmd Command) error {
    switch cmd {
    case CmdResetAllClasses:
        p.classes = make(map[string]ClassState)
        p.logger.Debug("reset all classes")
    
    case CmdResetActiveClasses:
        for name, state := range p.classes {
            if state == ClassActive {
                delete(p.classes, name)
            }
        }
        p.logger.Debug("reset active classes")
    
    case CmdResetCancelledClasses:
        for name, state := range p.classes {
            if state == ClassCancelled {
                delete(p.classes, name)
            }
        }
        p.logger.Debug("reset cancelled classes")
    
    default:
        return fmt.Errorf("unknown command: %s", cmd)
    }

    return nil
}

// Print outputs the final state to a writer
func (p *Parser) Print(w io.Writer) error {
    // Add completion marker
    p.classes["henc_classification_completed"] = ClassActive

    // Print classes in deterministic order (sorted by name)
    classNames := make([]string, 0, len(p.classes))
    for name := range p.classes {
        classNames = append(classNames, name)
    }
    
    // Sort for consistent output
    sortStrings(classNames)

    for _, name := range classNames {
        state := p.classes[name]
        var prefix string
        switch state {
        case ClassActive:
            prefix = "+"
        case ClassCancelled:
            prefix = "-"
        default:
            continue // Skip undefined
        }
        
        if _, err := fmt.Fprintf(w, "%s%s\n", prefix, name); err != nil {
            return fmt.Errorf("write class: %w", err)
        }
    }

    // Print variables (last assignment wins)
    varNames := make([]string, 0, len(p.variables))
    for name := range p.variables {
        varNames = append(varNames, name)
    }
    sortStrings(varNames)

    for _, name := range varNames {
        if _, err := fmt.Fprintf(w, "%s\n", p.variables[name]); err != nil {
            return fmt.Errorf("write variable: %w", err)
        }
    }

    return nil
}

// Simple string sort (could use slices.Sort in Go 1.21+)
func sortStrings(s []string) {
    for i := 0; i < len(s); i++ {
        for j := i + 1; j < len(s); j++ {
            if s[i] > s[j] {
                s[i], s[j] = s[j], s[i]
            }
        }
    }
}

// GetClasses returns a copy of the current classes
func (p *Parser) GetClasses() map[string]ClassState {
    result := make(map[string]ClassState, len(p.classes))
    for k, v := range p.classes {
        result[k] = v
    }
    return result
}

// GetVariables returns a copy of the current variables
func (p *Parser) GetVariables() map[string]string {
    result := make(map[string]string, len(p.variables))
    for k, v := range p.variables {
        result[k] = v
    }
    return result
}
