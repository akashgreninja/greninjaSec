package main

import "greninjaSec/cmd"

// Version is set via ldflags during build
var Version = "dev"

func main() {
	cmd.Version = Version
	cmd.Execute()
}
