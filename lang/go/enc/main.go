package main

import (
    "fmt"
    "log/slog"
    "os"

    "github.com/spf13/cobra"
    "github.com/yourorg/enc-parser/parser"
)

var (
    version = "dev"
    quiet   bool
    verbose bool
)

func main() {
    if err := newRootCmd().Execute(); err != nil {
        os.Exit(1)
    }
}

func newRootCmd() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "enc-parser [files...]",
        Short: "Parse External Node Classifier (ENC) files",
        Long: `Parse ENC files and output consolidated class and variable assignments.
        
ENC file format:
  +class_name          Add a class
  -class_name          Cancel a class
  _class_name          Reset/remove a class
  =var=value           Define a variable
  @array=val1,val2     Define an array
  %hash=key:val        Define a hash
  /var_name            Reset a variable
  !COMMAND             Execute special command
  
Special commands:
  !RESET_ALL_CLASSES
  !RESET_ACTIVE_CLASSES
  !RESET_CANCELLED_CLASSES`,
        Version: version,
        RunE:    run,
        Args:    cobra.MinimumNArgs(1),
    }

    cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
        "suppress all output except results")
    cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
        "enable verbose logging")

    return cmd
}

func run(cmd *cobra.Command, args []string) error {
    // Setup logging
    logLevel := slog.LevelWarn
    if verbose {
        logLevel = slog.LevelDebug
    }
    if quiet {
        logLevel = slog.LevelError
    }

    logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
        Level: logLevel,
    }))

    // Parse all files
    p := parser.New(logger)
    
    for _, filename := range args {
        if err := p.ParseFile(filename); err != nil {
            logger.Warn("failed to parse file",
                "file", filename,
                "error", err)
            continue
        }
        logger.Debug("parsed file successfully", "file", filename)
    }

    // Output results
    return p.Print(os.Stdout)
}
