// Command nzinga is the QYVORA authorized OSINT and intelligence collection
// framework.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-nzinga/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
