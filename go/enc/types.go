package parser

import "fmt"

// ClassState represents the state of a class
type ClassState int

const (
    ClassUndefined ClassState = 0  // Class not mentioned
    ClassActive    ClassState = 1  // Class added with +
    ClassCancelled ClassState = -1 // Class removed with -
)

func (cs ClassState) String() string {
    switch cs {
    case ClassActive:
        return "active"
    case ClassCancelled:
        return "cancelled"
    default:
        return "undefined"
    }
}

// SettingType represents the type of ENC setting
type SettingType rune

const (
    SettingCommand  SettingType = '!' // Special command
    SettingAddClass SettingType = '+' // Add class
    SettingDelClass SettingType = '-' // Remove class
    SettingResetClass SettingType = '_' // Reset class
    SettingVariable SettingType = '=' // Variable assignment
    SettingArray    SettingType = '@' // Array assignment
    SettingHash     SettingType = '%' // Hash assignment
    SettingResetVar SettingType = '/' // Reset variable
)

// Setting represents a parsed ENC directive
type Setting struct {
    Type  SettingType
    Value string
    Line  int // Line number for debugging
}

func (s Setting) String() string {
    return fmt.Sprintf("%c%s (line %d)", s.Type, s.Value, s.Line)
}

// Command represents special ENC commands
type Command string

const (
    CmdResetAllClasses       Command = "RESET_ALL_CLASSES"
    CmdResetActiveClasses    Command = "RESET_ACTIVE_CLASSES"
    CmdResetCancelledClasses Command = "RESET_CANCELLED_CLASSES"
)
