/*
*  Program for finding the preferred serial numbers of hard disks on a computer
*  Supports SATA, PATA, and NVMe drives
*  References code:
*    - CrystalDiskInfo project: https://github.com/hiyohiyo/CrystalDiskInfo
*/

#pragma once

#include <string>

namespace idfinder {
	std::string get_serial();
}
