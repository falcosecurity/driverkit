package cmd

import (
	"github.com/olekukonko/tablewriter"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
)

// NewImagesCmd creates the `driverkit images` command.
func NewImagesCmd(rootOpts *RootOptions, rootFlags *pflag.FlagSet) *cobra.Command {
	imagesCmd := &cobra.Command{
		Use:   "images",
		Short: "List builder images",
		Run: func(c *cobra.Command, args []string) {
			logger.WithField("processor", c.Name()).Info("listing images")
			b := rootOpts.ToBuild()
			b.LoadImages()

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Image", "Target", "Arch", "GCC"})
			table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
			table.SetCenterSeparator("|")

			for _, img := range b.Images {
				data := make([]string, 4)
				data[0] = img.Name
				data[1] = img.Target.String()
				data[2] = b.Architecture
				data[3] = img.GCCVersion.String()
				table.Append(data)
			}
			table.Render() // Send output
		},
	}
	// Add root flags
	imagesCmd.PersistentFlags().AddFlagSet(rootFlags)

	return imagesCmd
}
