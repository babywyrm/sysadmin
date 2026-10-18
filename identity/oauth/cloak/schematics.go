package main

// WarbirdSchematic represents the Romulan ship schematic details
type WarbirdSchematic struct {
	ShipName       string `json:"ship_name"`
	Blueprint      string `json:"blueprint"`
	Weakness       string `json:"weakness"`
	PowerOutput    string `json:"power_output"`
	DefenseSystems string `json:"defense_systems"`
}

// GetSchematics simulates retrieving Warbird schematics based on access level
func GetSchematics(level string) WarbirdSchematic {
	switch level {
	case "user":
		return WarbirdSchematic{
			ShipName: "Romulan Warbird - Basic",
			Blueprint: "Exterior Hull and Cloaking System - Class-I",
			Weakness: "Limited Plasma Reserves",
			PowerOutput: "Low-Level Plasma Reactor",
			DefenseSystems: "Energy Shields Only",
		}
	case "engineer":
		return WarbirdSchematic{
			ShipName: "Romulan Warbird - Engineering Level",
			Blueprint: "Type-II Warp Drive and Cloaking Core Layout",
			Weakness: "Overheating Cloak Core",
			PowerOutput: "Type-II Warp Plasma Core",
			DefenseSystems: "Shields & Plasma Torpedoes",
		}
	case "admin":
		return WarbirdSchematic{
			ShipName: "Romulan Warbird D'Deridex-Class",
			Blueprint: "Type-IV Cloaking Device & Plasma Torpedo Launcher",
			Weakness: "Overload Defense Matrix at Frequency 345Hz",
			PowerOutput: "High-Energy Quantum Plasma Reactor",
			DefenseSystems: "Quantum Shields, Disruptor Cannons",
		}
	default:
		return WarbirdSchematic{
			ShipName: "Unknown Vessel",
			Blueprint: "Access Restricted",
			Weakness: "N/A",
			PowerOutput: "N/A",
			DefenseSystems: "N/A",
		}
	}
}
