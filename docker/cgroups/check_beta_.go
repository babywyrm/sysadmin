//
// beta for a reason, tbh
// 

package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// ContainerStat holds a summary of container metrics.
type ContainerStat struct {
	ContainerName string  `json:"container_name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemUsage      uint64  `json:"mem_usage"`
	MemLimit      uint64  `json:"mem_limit"`
	MemPercent    float64 `json:"mem_percent"`
}

// calculateCPUPercentage computes CPU usage percentage using two snapshots.
func calculateCPUPercentage(stat *types.StatsJSON) float64 {
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage) - float64(stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage) - float64(stat.PreCPUStats.SystemUsage)
	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cores := float64(len(stat.CPUStats.CPUUsage.PercpuUsage))
		return (cpuDelta / systemDelta) * cores * 100.0
	}
	return 0.0
}

// monitorContainers lists all containers and gathers their stats.
func monitorContainers(cli *client.Client) ([]ContainerStat, error) {
	ctx := context.Background()
	containers, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing containers: %v", err)
	}

	var statsList []ContainerStat
	for _, container := range containers {
		stats, err := cli.ContainerStats(ctx, container.ID, false)
		if err != nil {
			log.Printf("Error fetching stats for container %s: %v", container.ID[:12], err)
			continue
		}
		// Decode stats JSON
		var statJSON types.StatsJSON
		decoder := json.NewDecoder(stats.Body)
		if err := decoder.Decode(&statJSON); err != nil {
			log.Printf("Error decoding stats for container %s: %v", container.ID[:12], err)
			stats.Body.Close()
			continue
		}
		stats.Body.Close()

		cpuPercent := calculateCPUPercentage(&statJSON)
		memUsage := statJSON.MemoryStats.Usage
		memLimit := statJSON.MemoryStats.Limit
		memPercent := 0.0
		if memLimit > 0 {
			memPercent = (float64(memUsage) / float64(memLimit)) * 100.0
		}

		containerName := ""
		if len(container.Names) > 0 {
			containerName = strings.TrimPrefix(container.Names[0], "/")
		} else {
			containerName = container.ID[:12]
		}

		statsList = append(statsList, ContainerStat{
			ContainerName: containerName,
			CPUPercent:    cpuPercent,
			MemUsage:      memUsage,
			MemLimit:      memLimit,
			MemPercent:    memPercent,
		})
	}

	// Sort by container name.
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].ContainerName < statsList[j].ContainerName
	})
	return statsList, nil
}

// outputTable prints container stats as a plain text table.
func outputTable(statsList []ContainerStat) {
	headers := []string{"Container", "CPU (%)", "Mem Usage", "Mem Limit", "Mem (%)"}
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	// Calculate column widths based on data.
	for _, stat := range statsList {
		if len(stat.ContainerName) > colWidths[0] {
			colWidths[0] = len(stat.ContainerName)
		}
		cpuStr := fmt.Sprintf("%.2f", stat.CPUPercent)
		memStr := fmt.Sprintf("%d", stat.MemUsage)
		limitStr := fmt.Sprintf("%d", stat.MemLimit)
		memPercStr := fmt.Sprintf("%.2f", stat.MemPercent)
		if len(cpuStr) > colWidths[1] {
			colWidths[1] = len(cpuStr)
		}
		if len(memStr) > colWidths[2] {
			colWidths[2] = len(memStr)
		}
		if len(limitStr) > colWidths[3] {
			colWidths[3] = len(limitStr)
		}
		if len(memPercStr) > colWidths[4] {
			colWidths[4] = len(memPercStr)
		}
	}
	// Print header.
	for i, h := range headers {
		fmt.Printf("%-*s  ", colWidths[i], h)
	}
	fmt.Println()
	// Print separator.
	for _, w := range colWidths {
		fmt.Printf("%s  ", strings.Repeat("-", w))
	}
	fmt.Println()
	// Print rows.
	for _, stat := range statsList {
		fmt.Printf("%-*s  %-*.2f  %-*d  %-*d  %-*.2f\n",
			colWidths[0], stat.ContainerName,
			colWidths[1], stat.CPUPercent,
			colWidths[2], stat.MemUsage,
			colWidths[3], stat.MemLimit,
			colWidths[4], stat.MemPercent)
	}
}

// outputCSV writes container stats as a CSV file.
func outputCSV(statsList []ContainerStat, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{"Container", "CPU (%)", "Mem Usage", "Mem Limit", "Mem (%)"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, stat := range statsList {
		row := []string{
			stat.ContainerName,
			fmt.Sprintf("%.2f", stat.CPUPercent),
			fmt.Sprintf("%d", stat.MemUsage),
			fmt.Sprintf("%d", stat.MemLimit),
			fmt.Sprintf("%.2f", stat.MemPercent),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// outputJSON writes container stats as a JSON array.
func outputJSON(statsList []ContainerStat, filename string) error {
	b, err := json.MarshalIndent(statsList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

func main() {
	socketPath := flag.String("socket", "unix:///var/run/docker.sock", "Docker socket to connect to")
	interval := flag.Duration("interval", 10*time.Second, "Interval between stats polling")
	outputFmt := flag.String("output", "table", "Output format: table, csv, json")
	flag.Parse()

	cli, err := client.NewClientWithOpts(client.WithHost(*socketPath), client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}

	// Monitoring loop.
	for {
		fmt.Println("Fetching container stats...")
		statsList, err := monitorContainers(cli)
		if err != nil {
			log.Printf("Error monitoring containers: %v", err)
		} else {
			switch *outputFmt {
			case "table":
				outputTable(statsList)
			case "csv":
				filename := fmt.Sprintf("docker_stats_%d.csv", time.Now().Unix())
				if err := outputCSV(statsList, filename); err != nil {
					log.Printf("Error writing CSV output: %v", err)
				} else {
					fmt.Printf("CSV output written to %s\n", filename)
				}
			case "json":
				filename := fmt.Sprintf("docker_stats_%d.json", time.Now().Unix())
				if err := outputJSON(statsList, filename); err != nil {
					log.Printf("Error writing JSON output: %v", err)
				} else {
					fmt.Printf("JSON output written to %s\n", filename)
				}
			default:
				fmt.Println("Unknown output format. Valid options are: table, csv, json")
			}
		}
		fmt.Printf("Sleeping for %v...\n", *interval)
		time.Sleep(*interval)
	}
}
