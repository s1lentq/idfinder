/*
*  Program for finding the preferred serial numbers of hard disks on a computer
*  Supports SATA, PATA, and NVMe drives
*  References code:
*    - CrystalDiskInfo project: https://github.com/hiyohiyo/CrystalDiskInfo
*/

#define WIN32_LEAN_AND_MEAN // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <winioctl.h>

#include "idfinder.h"

#include "StorageQuery.h"
#include "StorageDeviceDefs.h"

#include <vector>
#include <memory>
#include <iostream>
#include <string>
#include <cctype>
#include <algorithm>

#define USE_WMI 1
#define USE_DEBUG 1

#if USE_WMI
#define _WIN32_DCOM
#include <comdef.h>
#pragma warning(disable:4127)
#include <atlcomtime.h>
#pragma warning(default:4127)
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#endif

enum class INTERFACE_TYPE
{
	UNKNOWN = 0,
	PATA,	// Parallel ATA (legacy name ATA)
	SATA,	// Serial ATA
	NVME	// NVM Express
};

enum class DEVICE_DATA_SOURCE
{
	UNKNOWN,
	STORAGE_DESCRIPTOR,
	DRIVE_DATA,
	WMI
};

static const char *dataSourceTypeString[] =
{
	"Unknown",
	"Storage Descriptor",
	"Driver Data",
	"WMI"
};

enum class COMMAND_TYPE
{
	UNKNOWN = 0,
	PHYSICAL_DRIVE,
	WMI,
	NVME_SAMSUNG,
	NVME_INTEL,
	NVME_STORAGE_QUERY,
	NVME_INTEL_RST,
	NVME_INTEL_VROC
};

static const char *commandTypeString[] =
{
	"Unknown",
	"Physical drive",
	"WMI",
	"NVMe Samsung",
	"NVMe Intel",
	"NVMe Storage Query",
	"NVMe Intel RST",
	"NVMe Intel VROC"
};

// From winioctl.h Windows 10 SDK
#if defined(_USING_V110_SDK71_)
enum _EX_STORAGE_BUS_TYPE {
	BusTypeSpaces = BusTypeFileBackedVirtual + 1,
	BusTypeNvme,
	BusTypeSCM,
	BusTypeUfs
};
#else
using _EX_STORAGE_BUS_TYPE = _STORAGE_BUS_TYPE;
#endif

#define HANDLE_SUCCESS(hIoCtl) (hIoCtl && hIoCtl != INVALID_HANDLE_VALUE) // on some bugged systems, CreateFile may return NULL

// Finder for the hard drive ID
class CIDFinder
{
public:
	static const int MAX_DISK = 32; // FIX
	static const int MAX_SEARCH_PHYSICAL_DRIVE = 16;

	union IDENTIFY_DEVICE
	{
		ATA_IDENTIFY_DEVICE	 ATA;
		NVME_IDENTIFY_DEVICE NVME;
		BIN_IDENTIFY_DEVICE	 BIN;
	};

	void init();

#if USE_DEBUG
	void dump();
#endif

	std::string getSerialNumber() const;

protected:
	void				queryDevicesUsingWMI();
	void				queryDevicesUsingIOCTL();
	void				sortDisks();

	bool				addDisk(std::size_t physicalDriveId, INTERFACE_TYPE interfaceType, COMMAND_TYPE command, DEVICE_DATA_SOURCE source, const IDENTIFY_DEVICE &identify);
	bool				getDeviceData(HANDLE hIoCtrl, std::size_t physicalDriveId, INTERFACE_TYPE interfaceType);

	bool				containsNonPrintableChars(const char *str, std::size_t length) const;
	bool				doIdentifyDevicePd(HANDLE hIoCtrl, std::size_t physicalDriveId, std::uint8_t target, IDENTIFY_DEVICE &data);
	bool				doIdentifyDeviceNVMeStorageQuery(HANDLE hIoCtrl, IDENTIFY_DEVICE &data);

	HANDLE				openPhysicalDrive(const std::wstring &path, bool &bElevatedPermissions);

	// NVMe SAMSUNG
	bool				doIdentifyDeviceNVMeSamsung(HANDLE hIoCtrl, IDENTIFY_DEVICE &data);
	const std::wstring	getScsiPath(HANDLE hIoCtrl);

	// NVMe Intel
	bool				doIdentifyDeviceNVMeIntel(HANDLE hIoCtrl, IDENTIFY_DEVICE &data);
	bool				doIdentifyDeviceNVMeIntelVroc(HANDLE hIoCtrl, IDENTIFY_DEVICE &data);
	bool				doIdentifyDeviceNVMeIntelRst(HANDLE hIoCtrl, IDENTIFY_DEVICE &data);
	bool				getScsiAddress(HANDLE hIoCtrl, std::uint8_t &ubPortNumber, std::uint8_t &ubPathId, std::uint8_t &ubTargetId, std::uint8_t &ubLun) const;

	// OS methods
	bool		checkOSVersion();
	bool		isWindows10OrGreater() const;
	bool		isWindows8OrGreater() const;
	std::size_t	getSystemBootDriveNumber();

	enum IO_CONTROL_CODE : DWORD
	{
		DFP_SEND_DRIVE_COMMAND	= 0x0007C084,
		DFP_RECEIVE_DRIVE_DATA	= 0x0007C088,
		IOCTL_SCSI_MINIPORT		= 0x0004D008,
		IOCTL_IDE_PASS_THROUGH	= 0x0004D028, // 2000 or later
		IOCTL_ATA_PASS_THROUGH	= 0x0004D02C, // XP SP2 and 2003 or later
	};

	struct ATA_SMART_INFO
	{
		IDENTIFY_DEVICE		IdentifyDevice{};
		INTERFACE_TYPE		InterfaceType{};
		COMMAND_TYPE		CommandType{};
		DEVICE_DATA_SOURCE	DataSource{};

		std::size_t			PhysicalDriveId{};
		std::size_t			DriveLetterMap{};
		std::string			DriveMap;

		std::string			Model;
		std::string			SerialNumber;
		std::string			FirmwareRev;

		bool				BootFromDisk = false;
	};
	using DiskIter = std::vector<ATA_SMART_INFO>::iterator;

	template <typename T>
	bool	copyDeviceInfo(ATA_SMART_INFO &asi, const T &deviceInfo);
	bool	copyDeviceInfoFromStorage(ATA_SMART_INFO &asi, const STORAGE_DEVICE_DESCRIPTOR *deviceInfo);

public:
	static CIDFinder &get() {
		static CIDFinder instance{};
		return instance;
	}

private:
    CIDFinder(){}
    CIDFinder(const CIDFinder &) = delete;
    CIDFinder& operator=(const CIDFinder &) = delete;

private:
	std::vector<ATA_SMART_INFO> disks;
	RTL_OSVERSIONINFOEXW osvi{};
};

void CIDFinder::init()
{
	checkOSVersion();
#if USE_WMI
	queryDevicesUsingWMI(); // if any chance WMI then use it
#endif
	queryDevicesUsingIOCTL();
}

#if USE_WMI
void CIDFinder::queryDevicesUsingWMI()
{
	// Initialize COM
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		CoUninitialize();
		return; // Unable to initialize COM library
	}

	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE,
		NULL
	);

	if (FAILED(hr)) {
		CoUninitialize();
		return; // Failed to initialize security
	}

	{
		// Obtain the initial locator to WMI
		CComPtr<IWbemLocator> pLoc = NULL;
		hr = pLoc.CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER);
		if (FAILED(hr)) {
			CoUninitialize();
			return; // Failed to create IWbemLocator object
		}

		// Connect to WMI through the IWbemLocator::ConnectServer method
		CComPtr<IWbemServices> pSvc = NULL;

		if (isWindows8OrGreater())
		{
			// Connect to the root\microsoft\windows\storage namespace with
			// the current user and obtain pointer pSvc
			// to make IWbemServices calls.
			hr = pLoc->ConnectServer(
				_bstr_t(L"Root\\Microsoft\\Windows\\Storage"),	// Object path of WMI namespace
				NULL,						// User name. NULL = current user
				NULL,						// User password. NULL = current
				0,							// Locale. NULL indicates current
				NULL,						// Security flags.
				0,							// Authority (e.g. Kerberos)
				0,							// Context object
				&pSvc						// pointer to IWbemServices proxy
			);
		}
		else
		{
			// Connect to the root\cimv2 namespace with
			// the current user and obtain pointer pSvc
			// to make IWbemServices calls.
			hr = pLoc->ConnectServer(
				_bstr_t(L"ROOT\\CIMV2"),	// Object path of WMI namespace
				NULL,						// User name. NULL = current user
				NULL,						// User password. NULL = current
				0,							// Locale. NULL indicates current
				NULL,						// Security flags.
				0,							// Authority (e.g. Kerberos)
				0,							// Context object
				&pSvc						// pointer to IWbemServices proxy
			);
		}

		if (FAILED(hr)) {
			CoUninitialize();
			return; // Could not connect WMI service
		}

		//
		// Connected to selected WMI namespace

		// Set security levels on the proxy
		hr = CoSetProxyBlanket(
			pSvc,							// Indicates the proxy to set
			RPC_C_AUTHN_WINNT,				// RPC_C_AUTHN_xxx
			RPC_C_AUTHZ_NONE,				// RPC_C_AUTHZ_xxx
			NULL,							// Server principal name
			RPC_C_AUTHN_LEVEL_CALL,			// RPC_C_AUTHN_LEVEL_xxx
			RPC_C_IMP_LEVEL_IMPERSONATE,	// RPC_C_IMP_LEVEL_xxx
			NULL,							// client identity
			EOAC_NONE						// proxy capabilities
		);

		if (FAILED(hr)) {
			CoUninitialize();
			return; // Could not set proxy blanket
		}

		// Use the IWbemServices pointer to make requests of WMI
		CComPtr<IEnumWbemClassObject> pEnumerator = NULL;
		hr = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(
			isWindows8OrGreater() ?
			"SELECT Number,Model,FirmwareVersion,SerialNumber,BootFromDisk,BusType FROM MSFT_Disk" :
			"SELECT Index,Model,FirmwareRevision,PNPDeviceID,SerialNumber FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media'"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator
		);

		if (FAILED(hr)) {
			CoUninitialize();
			return; // Query for physical disk information failed
		}

		ULONG uReturn = 0;
		while (pEnumerator)
		{
			// Get the data from the above query
			CComPtr<IWbemClassObject> pclsObj = NULL;
			hr = pEnumerator->Next(5000, 1, &pclsObj, &uReturn);
			if (FAILED(hr) || uReturn == 0)
				break;

			//
			// Pluck a series of properties out of the query
			//

			_variant_t vtIndex{};
			hr = pclsObj->Get(isWindows8OrGreater() ? L"Number" : L"Index", 0, &vtIndex, NULL, NULL);
			if (FAILED(hr)) {
				continue;
			}

			bool BootFromDisk = false;
			INTERFACE_TYPE interfaceType = INTERFACE_TYPE::SATA; // assume that there is a SATA/PATA drive
			if (isWindows8OrGreater())
			{
				_variant_t vtBusType{};
				hr = pclsObj->Get(L"BusType", 0, &vtBusType, NULL, NULL);
				if (FAILED(hr)) {
					continue;
				}

				switch (vtBusType.cVal)
				{
				case BusTypeNvme: interfaceType = INTERFACE_TYPE::NVME; break;
				case BusTypeSata: interfaceType = INTERFACE_TYPE::SATA; break;
				case BusTypeAta:  interfaceType = INTERFACE_TYPE::PATA; break;
				default:
					continue; // bad interface
				}

				_variant_t vtBootFromDisk{};
				hr = pclsObj->Get(L"BootFromDisk", 0, &vtBootFromDisk, NULL, NULL);
				if (FAILED(hr)) {
					continue;
				}
				BootFromDisk = vtBootFromDisk.boolVal != 0;
			}
			// Workaround detecting NVME for earlier than 8
			else
			{
				_variant_t vtPNPDeviceID{};
				hr = pclsObj->Get(L"PNPDeviceID", 0, &vtPNPDeviceID, NULL, NULL);
				if (FAILED(hr) || !vtPNPDeviceID.bstrVal) {
					continue;
				}

				if (wcsstr(vtPNPDeviceID.bstrVal, L"NVME")) {
					interfaceType = INTERFACE_TYPE::NVME;
				}
			}

			_variant_t vtFirmwareVersion{};
			hr = pclsObj->Get(isWindows8OrGreater() ? L"FirmwareVersion" : L"FirmwareRevision", 0, &vtFirmwareVersion, NULL, NULL);
			if (FAILED(hr) || !vtFirmwareVersion.bstrVal) {
				continue;
			}

			_variant_t vtModel{};
			hr = pclsObj->Get(L"Model", 0, &vtModel, NULL, NULL);
			if (FAILED(hr) || !vtModel.bstrVal) {
				continue;
			}

			std::wstring wModel(vtModel.bstrVal);

			// Workaround for FuzeDrive (AMDStoreMi)
			if (wModel.find(L"FuzeDrive") != std::string::npos || wModel.find(L"StoreMI") != std::string::npos) {
				continue;
			}

			_variant_t vtSerialNumber{};
			hr = pclsObj->Get(L"SerialNumber", 0, &vtSerialNumber, NULL, NULL);
			if (FAILED(hr) || !vtSerialNumber.bstrVal) {
				continue;
			}

			IDENTIFY_DEVICE identify{};
			STORAGE_DEVICE_DESCRIPTOR *pDescriptor = (STORAGE_DEVICE_DESCRIPTOR *)&identify.BIN;
			if (interfaceType == INTERFACE_TYPE::NVME)
				pDescriptor->BusType = (STORAGE_BUS_TYPE)BusTypeNvme;
			else if (interfaceType == INTERFACE_TYPE::SATA)
				pDescriptor->BusType = BusTypeSata;
			else if (interfaceType == INTERFACE_TYPE::PATA)
				pDescriptor->BusType = BusTypeAta;

			{
				std::size_t woffs = 0;
				pDescriptor->VendorIdOffset = woffs;
				memset((char *)pDescriptor + pDescriptor->VendorIdOffset, 0, 28);
				woffs += 40;

				std::string sModel = StrUtil::ws2s(wModel);
				pDescriptor->ProductIdOffset = woffs;
				memcpy((char *)pDescriptor + pDescriptor->ProductIdOffset, sModel.c_str(), sModel.length());
				woffs += 40 + 1;

				std::string sFirmwareVersion = StrUtil::ws2s(vtFirmwareVersion.bstrVal);
				pDescriptor->ProductRevisionOffset = woffs;
				memcpy((char *)pDescriptor + pDescriptor->ProductRevisionOffset, sFirmwareVersion.c_str(), sFirmwareVersion.length());
				woffs += 8 + 1;

				std::string sSerialNumber = StrUtil::ws2s(vtSerialNumber.bstrVal);
				pDescriptor->SerialNumberOffset = woffs;
				memcpy((char *)pDescriptor + pDescriptor->SerialNumberOffset, sSerialNumber.c_str(), sSerialNumber.length());
				woffs += 20 + 1;
			}

			if (addDisk(vtIndex.uintVal, interfaceType, COMMAND_TYPE::PHYSICAL_DRIVE, DEVICE_DATA_SOURCE::WMI, identify) && isWindows8OrGreater()) {
				ATA_SMART_INFO &asi = disks.back();
				asi.BootFromDisk = BootFromDisk;
			}
		}
	}

	// Cleanup
	CoUninitialize();

	sortDisks();
}
#endif

typedef struct _VOLUME_DISK_EXTENTS_LX
{
	DWORD       NumberOfDiskExtents;
	DISK_EXTENT Extents[4];
} VOLUME_DISK_EXTENTS_LX, *PVOLUME_DISK_EXTENTS_LX;

void CIDFinder::queryDevicesUsingIOCTL()
{
	DWORD driveLetterMap[256]{0};

	// Scan physical drives
	for (std::size_t i = 0; i < MAX_SEARCH_PHYSICAL_DRIVE; i++)
	{
		bool bElevatedPermissions = true;
		std::wstring strDevice = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
		HANDLE hDevice = openPhysicalDrive(strDevice.c_str(), bElevatedPermissions);
		if (!HANDLE_SUCCESS(hDevice))
			continue;

		DISK_GEOMETRY dg{};
		DWORD dwBytesReturned = 0;
		if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(DISK_GEOMETRY), &dwBytesReturned, NULL)) {
			CloseHandle(hDevice);
			continue;
		}

		// only fixed media are scanned
		if (dwBytesReturned != sizeof(DISK_GEOMETRY) || dg.MediaType != FixedMedia) {
			CloseHandle(hDevice);
			continue;
		}

		// set the input data structure
		STORAGE_PROPERTY_QUERY storagePropertyQuery{};
		storagePropertyQuery.PropertyId              = StorageDeviceProperty;
		storagePropertyQuery.QueryType               = PropertyStandardQuery;
		storagePropertyQuery.AdditionalParameters[0] = 0;

		// get the necessary output buffer size
		STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader{};
		if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery,
			sizeof(STORAGE_PROPERTY_QUERY), &storageDescriptorHeader, sizeof(STORAGE_DESCRIPTOR_HEADER),
			&dwBytesReturned, NULL))
		{
			CloseHandle(hDevice);
			continue;
		}

		// has storage properties data?
		if (!storageDescriptorHeader.Size)
		{
			CloseHandle(hDevice);
			continue;
		}

		// alloc the output buffer
		const DWORD dwOutBufferSize = storageDescriptorHeader.Size;
		std::unique_ptr<BYTE []> outBuffer(new BYTE[dwOutBufferSize]);
		ZeroMemory(outBuffer.get(), dwOutBufferSize);

		if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery,
			sizeof(STORAGE_PROPERTY_QUERY), outBuffer.get(), dwOutBufferSize, &dwBytesReturned, NULL))
		{
			CloseHandle(hDevice);
			continue;
		}

		INTERFACE_TYPE interfaceType = INTERFACE_TYPE::UNKNOWN;

		STORAGE_DEVICE_DESCRIPTOR *pDescriptor = (STORAGE_DEVICE_DESCRIPTOR *)outBuffer.get();
		switch (pDescriptor->BusType) {
		case BusTypeNvme: interfaceType = INTERFACE_TYPE::NVME; break;
		case BusTypeSata: interfaceType = INTERFACE_TYPE::SATA; break;
		case BusTypeAta:  interfaceType = INTERFACE_TYPE::PATA;  break;
		default: {
			CloseHandle(hDevice);
			continue;
		}
		}

		std::string model;
		if (pDescriptor->ProductIdOffset) {
			model = (char *)pDescriptor + pDescriptor->ProductIdOffset;
		}

		// Workaround for FuzeDrive (AMDStoreMi)
		if (model.find("FuzeDrive") != std::string::npos || model.find("StoreMI") != std::string::npos) {
			CloseHandle(hDevice);
			continue;
		}

		if (getDeviceData(hDevice, i, interfaceType))
		{
			ATA_SMART_INFO &asi = disks.back();
			if (   asi.Model.find("DW C") != std::string::npos // WDC
				|| asi.Model.find("iHat") != std::string::npos // Hitachi
				|| asi.Model.find("ASSM") != std::string::npos // SAMSUNG
				|| asi.Model.find("aMtx") != std::string::npos // Maxtor
				|| asi.Model.find("OTHS") != std::string::npos // TOSHIBA
				|| asi.Model.find("UFIJ") != std::string::npos // FUJITSU
				)
			{
				StrUtil::change_byte_order(asi.SerialNumber);
				StrUtil::change_byte_order(asi.FirmwareRev);
				StrUtil::change_byte_order(asi.Model);

				asi.Model        = StrUtil::trim(asi.Model);
				asi.FirmwareRev  = StrUtil::trim(asi.FirmwareRev);
				asi.SerialNumber = StrUtil::trim(asi.SerialNumber);
			}
		}
		// If there are no elevated permissions, just try add disk from storage device descriptor,
		// but it incorrectly indicates the serialNumber for NVME
		else if (!bElevatedPermissions)
		{
			IDENTIFY_DEVICE identify{};
			switch (interfaceType) {
			case INTERFACE_TYPE::NVME: // nevermind, nvme serialNumber is not correct from storage device descriptor, just skip it
//				memcpy_s(&identify, sizeof(NVME_IDENTIFY_DEVICE), outBuffer.get(), sizeof(NVME_IDENTIFY_DEVICE));
//				AddDisk(i, interfaceType, COMMAND_TYPE::NVME_STORAGE_QUERY, DEVICE_DATA_SOURCE::STORAGE_DESCRIPTOR, identify);
				break;
			case INTERFACE_TYPE::SATA:
			case INTERFACE_TYPE::PATA:
				memcpy_s(&identify, sizeof(ATA_IDENTIFY_DEVICE), outBuffer.get(), sizeof(ATA_IDENTIFY_DEVICE));
				addDisk(i, interfaceType, COMMAND_TYPE::PHYSICAL_DRIVE, DEVICE_DATA_SOURCE::STORAGE_DESCRIPTOR, identify);
				break;
			default:
				break;
			}
		}

		// cleanup
		CloseHandle(hDevice);
	}

#if USE_DEBUG
	// Drive Letter Mapping http://www.cplusplus.com/forum/windows/12196/
	for (char c = 'A'; c <= 'Z'; c++)
	{
		std::wstring drive_path = L"";
		drive_path += c;
		drive_path += L":\\";

		std::size_t driver_type = GetDriveTypeW(drive_path.c_str());
		if (driver_type != DRIVE_FIXED)
			continue;

		std::wstring path = L"\\\\.\\";
		path += c;
		path += L":";

		HANDLE hHandle = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hHandle || hHandle == INVALID_HANDLE_VALUE)
			continue;

		VOLUME_DISK_EXTENTS_LX volumeDiskExtents{};
		DWORD dwBytesReturned = 0;
		BOOL bResult = DeviceIoControl(hHandle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
			&volumeDiskExtents, sizeof(volumeDiskExtents), &dwBytesReturned, NULL);
		CloseHandle(hHandle);
		if (!bResult)
			continue;

		for (DWORD n = 0; n < volumeDiskExtents.NumberOfDiskExtents && volumeDiskExtents.NumberOfDiskExtents < 4; ++n)
		{
			PDISK_EXTENT pDiskExtent = &volumeDiskExtents.Extents[n];
			if (pDiskExtent->ExtentLength.QuadPart == 0)
				continue;

			if (0 <= pDiskExtent->DiskNumber && pDiskExtent->DiskNumber < 256)
				driveLetterMap[pDiskExtent->DiskNumber] |= 1 << (c - 'A');
		}
	}

	for (ATA_SMART_INFO &asi : disks)
	{
		if (asi.PhysicalDriveId < 0)
			continue;

		const int ALPHABET_SIZE = 'z' - 'a' + 1;
		for (int j = 0; j < ALPHABET_SIZE; j++)
		{
			if (driveLetterMap[asi.PhysicalDriveId] & (1 << j))
			{
				asi.DriveMap.push_back(j + 'A');
				asi.DriveMap.append(": ");

				if (asi.PhysicalDriveId != 2)
					asi.DriveLetterMap += (1 << j);
			}
		}

		asi.DriveMap = StrUtil::trim(asi.DriveMap);
	}
#endif // USE_DEBUG

	sortDisks();
}

// Sorting disks in ascending order of letters and system attribute
void CIDFinder::sortDisks()
{
	std::sort(disks.begin(), disks.end(), [](const ATA_SMART_INFO &a, const ATA_SMART_INFO &b)
	{
		if (a.BootFromDisk && !b.BootFromDisk)
			return true;

		if (!a.BootFromDisk && b.BootFromDisk)
			return false;

		int dlm1 = -1;
		int dlm2 = -1;

		const int ALPHABET_SIZE = 'z' - 'a' + 1;

		for (int i = 0; i < ALPHABET_SIZE; i++)
		{
			if (a.DriveLetterMap & (1 << i)) {
				dlm1 = i; break;
			}
		}

		for (int i = 0; i < ALPHABET_SIZE; i++)
		{
			if (b.DriveLetterMap & (1 << i)) {
				dlm2 = i; break;
			}
		}

		int pdi1 = a.PhysicalDriveId;
		int pdi2 = b.PhysicalDriveId;
		if (pdi1 == -1) pdi1 = 255;
		if (pdi2 == -1) pdi2 = 255;
		if (dlm1 == -1) dlm1 = ALPHABET_SIZE + 1;
		if (dlm2 == -1) dlm2 = ALPHABET_SIZE + 1;

		dlm1++;
		dlm2++;

		int sort1 = (dlm1 << 8) + pdi1;
		int sort2 = (dlm2 << 8) + pdi2;
		return sort1 < sort2;
	});
}

HANDLE CIDFinder::openPhysicalDrive(const std::wstring &path, bool &bElevatedPermissions)
{
	// try open with elevated permissions
	HANDLE hIoCtrl = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, // NOTE: requeriment elevated permissions
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	bElevatedPermissions = true;

	// try open again but without permissions
	if (!HANDLE_SUCCESS(hIoCtrl))
	{
		hIoCtrl = CreateFileW(path.c_str(), 0,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		bElevatedPermissions = false;
	}

	return hIoCtrl;
}

bool CIDFinder::getDeviceData(HANDLE hIoCtrl, std::size_t physicalDriveId, INTERFACE_TYPE interfaceType)
{
	IDENTIFY_DEVICE identify{};
	COMMAND_TYPE command = COMMAND_TYPE::UNKNOWN;
	switch (interfaceType)
	{
	default:
	case INTERFACE_TYPE::PATA:
	case INTERFACE_TYPE::SATA:
	{
		// ATA Commands Register
		const int DRIVE_HEAD_REG    = 0xA0;
		const int SMART_EXECUTE_CMD = 0xB0;
		if (doIdentifyDevicePd(hIoCtrl, physicalDriveId, DRIVE_HEAD_REG, identify))
			command = COMMAND_TYPE::PHYSICAL_DRIVE;
		else if (doIdentifyDevicePd(hIoCtrl, physicalDriveId, SMART_EXECUTE_CMD, identify))
			command = COMMAND_TYPE::PHYSICAL_DRIVE;
		break;
	}
	case INTERFACE_TYPE::NVME:
	{
		if (isWindows10OrGreater() && doIdentifyDeviceNVMeStorageQuery(hIoCtrl, identify))
			command = COMMAND_TYPE::NVME_STORAGE_QUERY;
		else if (doIdentifyDeviceNVMeIntelVroc(hIoCtrl, identify))
			command = COMMAND_TYPE::NVME_INTEL_VROC;
		else if (doIdentifyDeviceNVMeIntelRst(hIoCtrl, identify))
			command = COMMAND_TYPE::NVME_INTEL_RST;
		else if (doIdentifyDeviceNVMeSamsung(hIoCtrl, identify))
			command = COMMAND_TYPE::NVME_SAMSUNG;
		else if (doIdentifyDeviceNVMeIntel(hIoCtrl, identify))
			command = COMMAND_TYPE::NVME_INTEL;
		break;
	}
	}

	return addDisk(physicalDriveId, interfaceType, command, DEVICE_DATA_SOURCE::DRIVE_DATA, identify);
}

bool CIDFinder::doIdentifyDevicePd(HANDLE hIoCtrl, std::size_t physicalDriveId, std::uint8_t target, IDENTIFY_DEVICE &data)
{
	ZeroMemory(&data, sizeof(data));

	IDENTIFY_DEVICE_OUTDATA	sendCmdOutParam{};
	SENDCMDINPARAMS	sendCmd{};
	sendCmd.irDriveRegs.bCommandReg      = ID_CMD;
	sendCmd.irDriveRegs.bFeaturesReg     = 0;
	sendCmd.irDriveRegs.bSectorCountReg  = 1;
	sendCmd.irDriveRegs.bSectorNumberReg = 1;
	sendCmd.cBufferSize                  = IDENTIFY_BUFFER_SIZE;
	sendCmd.irDriveRegs.bDriveHeadReg    = target;// | ((physicalDriveId & 1) << 4);

	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hIoCtrl, DFP_RECEIVE_DRIVE_DATA,
		&sendCmd, sizeof(SENDCMDINPARAMS),
		&sendCmdOutParam, sizeof(IDENTIFY_DEVICE_OUTDATA),
		&dwBytesReturned, NULL))
		return false;

	if (dwBytesReturned != sizeof(IDENTIFY_DEVICE_OUTDATA))
		return false;

	memcpy_s(&data, sizeof(ATA_IDENTIFY_DEVICE), sendCmdOutParam.SendCmdOutParam.bBuffer, sizeof(ATA_IDENTIFY_DEVICE));
	return true;
}

//
//  NVMe SAMSUNG
//
bool CIDFinder::doIdentifyDeviceNVMeSamsung(HANDLE hIoCtrl, IDENTIFY_DEVICE &data)
{
	ZeroMemory(&data, sizeof(data));

	SCSI_PASS_THROUGH_WITH_BUFFERS24 sptwb{};
	sptwb.Spt.Length             = sizeof(SCSI_PASS_THROUGH);
	sptwb.Spt.PathId             = 0;
	sptwb.Spt.TargetId           = 0;
	sptwb.Spt.Lun                = 0;
	sptwb.Spt.SenseInfoLength    = 24;
	sptwb.Spt.DataIn             = SCSI_IOCTL_DATA_IN;
	sptwb.Spt.DataTransferLength = 4096;
	sptwb.Spt.TimeOutValue       = 2;
	sptwb.Spt.DataBufferOffset   = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS24, DataBuf);
	sptwb.Spt.SenseInfoOffset    = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS24, SenseBuf);
	sptwb.Spt.CdbLength          = 16;
	sptwb.Spt.Cdb[0]             = 0xB5; // SECURITY PROTOCOL OUT
	sptwb.Spt.Cdb[1]             = 0xFE; // SAMSUNG PROTOCOL
	sptwb.Spt.Cdb[2]             = 0;
	sptwb.Spt.Cdb[3]             = 5;
	sptwb.Spt.Cdb[4]             = 0;
	sptwb.Spt.Cdb[5]             = 0;
	sptwb.Spt.Cdb[6]             = 0;
	sptwb.Spt.Cdb[7]             = 0;
	sptwb.Spt.Cdb[8]             = 0;
	sptwb.Spt.Cdb[9]             = 0x40;
	sptwb.Spt.DataIn             = SCSI_IOCTL_DATA_OUT;
	sptwb.DataBuf[0]             = 1;

	DWORD dwBytesReturned = 0;
	DWORD length = offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS24, DataBuf) + sptwb.Spt.DataTransferLength;
	if (!DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH,
		&sptwb, length, &sptwb, length, &dwBytesReturned, NULL))
		return false;

	sptwb.Spt.CdbLength = 16;
	sptwb.Spt.Cdb[0]    = 0xA2; // SECURITY PROTOCOL IN
	sptwb.Spt.Cdb[1]    = 0xFE; // SAMSUNG PROTOCOL
	sptwb.Spt.Cdb[2]    = 0;
	sptwb.Spt.Cdb[3]    = 5;
	sptwb.Spt.Cdb[4]    = 0;
	sptwb.Spt.Cdb[5]    = 0;
	sptwb.Spt.Cdb[6]    = 0;
	sptwb.Spt.Cdb[7]    = 0;
	sptwb.Spt.Cdb[8]    = 1;
	sptwb.Spt.Cdb[9]    = 0;
	sptwb.Spt.DataIn    = SCSI_IOCTL_DATA_IN;
	sptwb.DataBuf[0]    = 0;

	if (!DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH,
		&sptwb, length, &sptwb, length, &dwBytesReturned, NULL))
		return false;

	std::size_t count = 0;
	for (int i = 0; i < 512; i++)
		count += sptwb.DataBuf[i];

	if (count == 0)
		return false;

	memcpy_s(&data, sizeof(NVME_IDENTIFY_DEVICE), sptwb.DataBuf, sizeof(NVME_IDENTIFY_DEVICE));
	return true;
}

//
// NVMe Intel
// Reference: http://web.archive.org/web/20160506200118/http://naraeon.net/en/archives/1126
//
const std::wstring CIDFinder::getScsiPath(HANDLE hIoCtrl)
{
	SCSI_ADDRESS sadr{};
	DWORD dwBytesReturned = 0;
	if (DeviceIoControl(hIoCtrl, IOCTL_SCSI_GET_ADDRESS,
		NULL, 0, &sadr, sizeof(sadr), &dwBytesReturned, NULL))
		return std::wstring(L"\\\\.\\PhysicalDrive" + std::to_wstring(sadr.PortNumber));

	return std::wstring{};
}

bool CIDFinder::doIdentifyDeviceNVMeIntel(HANDLE hIoCtrl, IDENTIFY_DEVICE &data)
{
	ZeroMemory(&data, sizeof(data));

	std::wstring strScsiDrive = getScsiPath(hIoCtrl);
	if (strScsiDrive.empty())
		return false;

	HANDLE hIoScsiCtrl = CreateFileW(strScsiDrive.c_str(), GENERIC_READ | GENERIC_WRITE, // TODO: REQUERIMENT ADMIN RIGHTS
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!HANDLE_SUCCESS(hIoScsiCtrl))
		return false;

	NVME_PASS_THROUGH_IOCTL nptwb{};
	DWORD length = sizeof(nptwb);

	memcpy((UCHAR *)(&nptwb.SrbIoCtrl.Signature[0]), NVME_SIG_STR, NVME_SIG_STR_LEN);
	nptwb.SrbIoCtrl.ControlCode  = NVME_PASS_THROUGH_SRB_IO_CODE;
	nptwb.SrbIoCtrl.HeaderLength = sizeof(SRB_IO_CONTROL);
	nptwb.SrbIoCtrl.Timeout      = NVME_PT_TIMEOUT;
	nptwb.SrbIoCtrl.Length       = length - sizeof(SRB_IO_CONTROL);
	nptwb.DataBufferLen          = sizeof(nptwb.DataBuffer);
	nptwb.ReturnBufferLen        = sizeof(nptwb);
	nptwb.Direction              = NVME_FROM_DEV_TO_HOST;

	nptwb.NVMeCmd[0]  = 6; // Identify
	nptwb.NVMeCmd[1]  = 0; // Namespace Identifier (CDW1.NSID)
	nptwb.NVMeCmd[10] = 1; // Controller or Namespace Structure (CNS)

	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hIoScsiCtrl, IOCTL_SCSI_MINIPORT,
		&nptwb, length, &nptwb, length, &dwBytesReturned, NULL))
	{
		CloseHandle(hIoScsiCtrl);
		return false;
	}

	std::size_t count = 0;
	for (int i = 0; i < 512; i++)
		count += nptwb.DataBuffer[i];

	if (count == 0)
	{
		CloseHandle(hIoScsiCtrl);
		return false;
	}

	memcpy_s(&data, sizeof(NVME_IDENTIFY_DEVICE), nptwb.DataBuffer, sizeof(NVME_IDENTIFY_DEVICE));
	CloseHandle(hIoScsiCtrl);
	return true;
}

//
// NVMe Intel RST
//
bool CIDFinder::getScsiAddress(
	HANDLE hIoCtrl,
	std::uint8_t &ubPortNumber,
	std::uint8_t &ubPathId,
	std::uint8_t &ubTargetId,
	std::uint8_t &ubLun) const
{
	DWORD dwBytesReturned = 0;
	SCSI_ADDRESS ScsiAddr{};
	if (!DeviceIoControl(hIoCtrl, IOCTL_SCSI_GET_ADDRESS,
		NULL, 0, &ScsiAddr, sizeof(ScsiAddr), &dwBytesReturned, NULL))
	{
		return false;
	}

	ubPortNumber = ScsiAddr.PortNumber;
	ubPathId     = ScsiAddr.PathId;
	ubTargetId   = ScsiAddr.TargetId;
	ubLun        = ScsiAddr.Lun;

	return true;
}

bool CIDFinder::doIdentifyDeviceNVMeIntelRst(HANDLE hIoCtrl, IDENTIFY_DEVICE &data)
{
	std::uint8_t portNumber = 0, pathId = 0, targetId = 0, lun = 0;
	if (!getScsiAddress(hIoCtrl, portNumber, pathId, targetId, lun))
		return false;

	std::wstring strScsiDrive = L"\\\\.\\Scsi%d:" + std::to_wstring(portNumber);
	HANDLE hIoScsiCtrl = CreateFileW(strScsiDrive.c_str(), GENERIC_READ | GENERIC_WRITE, // TODO: REQUERIMENT ADMIN RIGHTS
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (!HANDLE_SUCCESS(hIoScsiCtrl))
		return false;

	INTEL_NVME_PASS_THROUGH NVMeData;
	memset(&NVMeData, 0, sizeof(NVMeData));

	NVMeData.SRB.HeaderLength = sizeof(SRB_IO_CONTROL);
	memcpy(NVMeData.SRB.Signature, "IntelNvm", 8);
	NVMeData.SRB.Timeout = 10;
	NVMeData.SRB.ControlCode = IOCTL_INTEL_NVME_PASS_THROUGH;
	NVMeData.SRB.Length = sizeof(INTEL_NVME_PASS_THROUGH) - sizeof(SRB_IO_CONTROL);

	NVMeData.Payload.Version = 1;
	NVMeData.Payload.PathId = pathId;
	NVMeData.Payload.Cmd.CDW0.Opcode = 0x06; // ADMIN_IDENTIFY
	NVMeData.Payload.Cmd.NSID = 0;
	NVMeData.Payload.Cmd.u.IDENTIFY.CDW10.CNS = 1;
	NVMeData.Payload.ParamBufLen = sizeof(INTEL_NVME_PAYLOAD) + sizeof(SRB_IO_CONTROL); //0xA4;
	NVMeData.Payload.ReturnBufferLen = 0x1000;
	NVMeData.Payload.CplEntry[0] = 0;

	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hIoScsiCtrl, IOCTL_SCSI_MINIPORT,
		&NVMeData, sizeof(NVMeData), &NVMeData, sizeof(NVMeData), &dwBytesReturned, NULL))
	{
		CloseHandle(hIoScsiCtrl);
		return false;
	}

	memcpy_s(&data, sizeof(NVME_IDENTIFY_DEVICE), NVMeData.DataBuffer, sizeof(NVME_IDENTIFY_DEVICE));
	CloseHandle(hIoScsiCtrl);
	return TRUE;
}

//
// NVMe Intel VROC
//
bool CIDFinder::doIdentifyDeviceNVMeIntelVroc(HANDLE hIoCtrl, IDENTIFY_DEVICE &data)
{
	ZeroMemory(&data, sizeof(data));

	std::uint8_t portNumber = 0, pathId = 0, targetId = 0, lun = 0;
	if (!getScsiAddress(hIoCtrl, portNumber, pathId, targetId, lun))
		return false;

	std::wstring strScsiDrive = L"\\\\.\\Scsi%d:" + std::to_wstring(portNumber);
	HANDLE hIoScsiCtrl = CreateFileW(strScsiDrive.c_str(), GENERIC_READ | GENERIC_WRITE, // TODO: REQUERIMENT ADMIN RIGHTS
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!HANDLE_SUCCESS(hIoScsiCtrl))
		return false;

	NVME_PASS_THROUGH_IOCTL nptwb{};
	DWORD length = sizeof(nptwb);

	memcpy((UCHAR *)(&nptwb.SrbIoCtrl.Signature[0]), "NvmeRAID", NVME_SIG_STR_LEN);
	nptwb.SrbIoCtrl.ControlCode  = NVME_PASS_THROUGH_SRB_IO_CODE;
	nptwb.SrbIoCtrl.Timeout      = NVME_PT_TIMEOUT;
	nptwb.SrbIoCtrl.HeaderLength = sizeof(SRB_IO_CONTROL);
	nptwb.SrbIoCtrl.Length       = length - sizeof(SRB_IO_CONTROL);
	nptwb.SrbIoCtrl.ReturnCode   = 0x86000000 + (pathId << 16) + (targetId << 8) + lun;

	nptwb.Direction       = NVME_FROM_DEV_TO_HOST;
	nptwb.QueueId         = 0;
	nptwb.MetaDataLen     = 0;
	nptwb.DataBufferLen   = sizeof(nptwb.DataBuffer);
	nptwb.ReturnBufferLen = sizeof(nptwb);
	nptwb.NVMeCmd[0]      = 6; // Identify
	nptwb.NVMeCmd[1]      = 0; // Namespace Identifier (CDW1.NSID)
	nptwb.NVMeCmd[10]     = 1; // Controller or Namespace Structure (CNS)
	nptwb.DataBuffer[0]   = TRUE;

	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hIoScsiCtrl, IOCTL_SCSI_MINIPORT,
		&nptwb, length, &nptwb, length, &dwBytesReturned, NULL))
	{
		CloseHandle(hIoScsiCtrl);
		return false;
	}

	std::size_t count = 0;
	for (int i = 0; i < 512; i++)
		count += nptwb.DataBuffer[i];

	if (count == 0) {
		CloseHandle(hIoScsiCtrl);
		return false;
	}

	memcpy_s(&data, sizeof(NVME_IDENTIFY_DEVICE), nptwb.DataBuffer, sizeof(NVME_IDENTIFY_DEVICE));
	CloseHandle(hIoScsiCtrl);
	return true;
}

// NVMe Storage Query
// Reference: http://web.archive.org/web/20160604013727/http://http://naraeon.net/en/archives/1338
bool CIDFinder::doIdentifyDeviceNVMeStorageQuery(HANDLE hIoCtrl, IDENTIFY_DEVICE &data)
{
	StorageQuery::TStorageQueryWithBuffer nptwb{};
	nptwb.ProtocolSpecific.ProtocolType                = StorageQuery::ProtocolTypeNvme;
	nptwb.ProtocolSpecific.DataType                    = StorageQuery::NVMeDataTypeIdentify;
	nptwb.ProtocolSpecific.ProtocolDataOffset          = sizeof(StorageQuery::TStorageProtocolSpecificData);
	nptwb.ProtocolSpecific.ProtocolDataLength          = 4096;
	nptwb.Query.PropertyId                             = StorageQuery::StorageAdapterProtocolSpecificProperty;
	nptwb.Query.QueryType                              = StorageQuery::PropertyStandardQuery;
	nptwb.ProtocolSpecific.ProtocolDataRequestValue    = 1; /*NVME_IDENTIFY_CNS_CONTROLLER*/
	nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = 0;

	DWORD dwBytesReturned = 0;
	if (!DeviceIoControl(hIoCtrl, IOCTL_STORAGE_QUERY_PROPERTY,
		&nptwb, sizeof(nptwb), &nptwb, sizeof(nptwb), &dwBytesReturned, NULL))
	{
		return false;
	}

	memcpy_s(&data, sizeof(NVME_IDENTIFY_DEVICE), nptwb.Buffer, sizeof(NVME_IDENTIFY_DEVICE));
	return true;
}

bool CIDFinder::containsNonPrintableChars(const char *str, std::size_t length) const
{
	return std::any_of(str, str + length, [](char c) {
		return !std::isprint(static_cast<unsigned char>(c));
	});
}

bool CIDFinder::copyDeviceInfoFromStorage(ATA_SMART_INFO &asi, const STORAGE_DEVICE_DESCRIPTOR *deviceInfo)
{
	char buf[64]{};

	if (deviceInfo->ProductIdOffset)
	{
		strncpy_s(buf, sizeof(buf), (char *)deviceInfo + deviceInfo->ProductIdOffset, sizeof(buf));

		asi.Model = buf;
		asi.Model = asi.Model.substr(0, 40);
	}

	if (deviceInfo->ProductRevisionOffset)
	{
		strncpy_s(buf, sizeof(buf), (char *)deviceInfo + deviceInfo->ProductRevisionOffset, sizeof(buf));

		asi.FirmwareRev = buf;
		asi.FirmwareRev = asi.FirmwareRev.substr(0, 8);
	}

	if (deviceInfo->SerialNumberOffset)
	{
		strncpy_s(buf, sizeof(buf), (char *)deviceInfo + deviceInfo->SerialNumberOffset, sizeof(buf));
		asi.SerialNumber = buf;
		asi.SerialNumber = asi.SerialNumber.substr(0, 40);
	}

	// windows versions earlier than 8 contains serialnumber in vice versa
	bool shouldFlipBytes = !isWindows8OrGreater();
	if (shouldFlipBytes)
		StrUtil::change_byte_order(asi.SerialNumber);

	asi.Model        = StrUtil::trim(asi.Model);
	asi.FirmwareRev  = StrUtil::trim(asi.FirmwareRev);
	asi.SerialNumber = StrUtil::trim(asi.SerialNumber);

	// bad serialNumber
	if (asi.SerialNumber.find("0000_0000_0000_") != std::string::npos)
		return false;

	return true;
}

template <typename T>
bool CIDFinder::copyDeviceInfo(ATA_SMART_INFO &asi, const T &deviceInfo)
{
	char buf[64]{};

	strncpy_s(buf, sizeof(buf), deviceInfo.Model, sizeof(deviceInfo.Model));
	asi.Model = buf;
	asi.Model = asi.Model.substr(0, 40);

	strncpy_s(buf, sizeof(buf), deviceInfo.FirmwareRev, sizeof(deviceInfo.FirmwareRev));
	asi.FirmwareRev = buf;
	asi.FirmwareRev = asi.FirmwareRev.substr(0, 8);

	strncpy_s(buf, sizeof(buf), deviceInfo.SerialNumber, sizeof(deviceInfo.SerialNumber));
	asi.SerialNumber = buf;
	asi.SerialNumber = asi.SerialNumber.substr(0, 40);

	// If this is an ATA device, change the byte order
	if (asi.InterfaceType != INTERFACE_TYPE::NVME)
	{
		StrUtil::change_byte_order(asi.Model);
		StrUtil::change_byte_order(asi.FirmwareRev);
		StrUtil::change_byte_order(asi.SerialNumber);
	}

	// Ensure no leading spaces after reorder bytes
	asi.Model        = StrUtil::trim(asi.Model);
	asi.FirmwareRev  = StrUtil::trim(asi.FirmwareRev);
	asi.SerialNumber = StrUtil::trim(asi.SerialNumber);

	return true;
}

bool CIDFinder::addDisk(std::size_t physicalDriveId, INTERFACE_TYPE interfaceType, COMMAND_TYPE command, DEVICE_DATA_SOURCE source, const IDENTIFY_DEVICE &identify)
{
	if (command == COMMAND_TYPE::UNKNOWN)
		return false;

	ATA_SMART_INFO asi{};
	asi.IdentifyDevice      = identify;
	asi.PhysicalDriveId     = physicalDriveId;
	asi.DriveLetterMap      = 0;
	asi.InterfaceType       = interfaceType;
	asi.CommandType         = command;
	asi.DataSource          = source;

	if (source == DEVICE_DATA_SOURCE::STORAGE_DESCRIPTOR || source == DEVICE_DATA_SOURCE::WMI)
	{
		if (!copyDeviceInfoFromStorage(asi, (STORAGE_DEVICE_DESCRIPTOR *)&identify.BIN))
			return false; // bad storage device data
	}
	else if (interfaceType == INTERFACE_TYPE::NVME)
	{
		copyDeviceInfo(asi, identify.NVME);
	}
	else if (interfaceType == INTERFACE_TYPE::PATA || interfaceType == INTERFACE_TYPE::SATA)
	{
		if (containsNonPrintableChars(identify.ATA.SerialNumber, sizeof(identify.ATA.SerialNumber)) ||
			containsNonPrintableChars(identify.ATA.FirmwareRev, sizeof(identify.ATA.FirmwareRev)) ||
			containsNonPrintableChars(identify.ATA.Model, sizeof(identify.ATA.Model))) {
			return false;
		}

		copyDeviceInfo(asi, identify.ATA); // SATA, PATA have the same set of structure info
	}

	// Mark the drive where the system should boot
	if (asi.PhysicalDriveId == getSystemBootDriveNumber())
		asi.BootFromDisk = true;

//	if (asi.SerialNumber.empty())
//		return false;

	// Check overlap
	DiskIter &it = std::find_if(disks.begin(), disks.end(), [&](ATA_SMART_INFO &info) {
		return info.PhysicalDriveId == physicalDriveId;
	});

	if (it != disks.end()) {
		// update device info
		ATA_SMART_INFO &device = (*it);
		device.IdentifyDevice  = asi.IdentifyDevice;
		device.InterfaceType   = asi.InterfaceType;
		device.CommandType     = asi.CommandType;
		device.DataSource      = asi.DataSource;
		device.PhysicalDriveId = asi.PhysicalDriveId;
		device.DriveLetterMap  = asi.DriveLetterMap;
		device.DriveMap        = asi.DriveMap;
		device.Model           = asi.Model;
		device.SerialNumber    = asi.SerialNumber;
		device.FirmwareRev     = asi.FirmwareRev;
		if (!device.BootFromDisk)
			device.BootFromDisk = asi.BootFromDisk;
	} else {
		if (disks.size() >= MAX_DISK)
			return false;
		disks.emplace_back(asi);
	}

	return true;
}

std::size_t CIDFinder::getSystemBootDriveNumber()
{
	static std::size_t system_boot_on_driveid = -1;
	if (system_boot_on_driveid != -1)
		return system_boot_on_driveid;

	const char *sys_drive = getenv("SystemDrive");
	if (sys_drive && sys_drive[0])
	{
		std::wstring systemDrive = L"\\\\.\\";
		systemDrive += sys_drive[0];
		systemDrive += L":";

		HANDLE hSystemDrive = CreateFileW(systemDrive.c_str(), 0, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (HANDLE_SUCCESS(hSystemDrive))
		{
			STORAGE_DEVICE_NUMBER info{};
			DWORD dwBytesReturned = 0;
			if (DeviceIoControl(hSystemDrive, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &info, sizeof(info), &dwBytesReturned, NULL)) {
				system_boot_on_driveid = info.DeviceNumber;
			}

			CloseHandle(hSystemDrive);
		}
	}

	return system_boot_on_driveid;
}

std::string CIDFinder::getSerialNumber() const
{
	for (const ATA_SMART_INFO &asi : disks)
	{
		if (asi.SerialNumber.empty()) continue;
		return asi.SerialNumber;
	}

	DWORD dwVolumeSerialNumber = 0;
	if (!GetVolumeInformationA(NULL, NULL, 0, &dwVolumeSerialNumber, NULL, NULL, NULL, 0))
		return std::string{};

	return std::to_string(dwVolumeSerialNumber);
}

bool CIDFinder::checkOSVersion()
{
	HMODULE hNTdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNTdll)
		return false;

	ZeroMemory(&osvi, sizeof(osvi));
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	typedef LONG (WINAPI *RtlGetVersionFunc_t)(PRTL_OSVERSIONINFOW lpVersionInformation);
	RtlGetVersionFunc_t DynRtlGetVersion = (RtlGetVersionFunc_t)GetProcAddress(hNTdll, "RtlGetVersion");
	if (DynRtlGetVersion && DynRtlGetVersion((RTL_OSVERSIONINFOW *)&osvi) == 0)
		return true;

	return false;
}

bool CIDFinder::isWindows10OrGreater() const
{
	return ((osvi.dwMajorVersion > 10) || ((osvi.dwMajorVersion == 10) && (osvi.dwMinorVersion >= 0)));
}

bool CIDFinder::isWindows8OrGreater() const
{
	return ((osvi.dwMajorVersion > 6) || ((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 2)));
}

namespace idfinder {
	std::string get_serial() { return CIDFinder::get().getSerialNumber(); }
}

#if USE_DEBUG
void CIDFinder::dump()
{
	for (const ATA_SMART_INFO &asi : disks)
	{
		if (asi.PhysicalDriveId < 0)
			continue;

        std::cout << "\t\\\\.\\PhysicalDrive" << asi.PhysicalDriveId << std::endl;

        std::string interfaceTypeStr;
        if (asi.InterfaceType == INTERFACE_TYPE::PATA)
            interfaceTypeStr = "PATA ";
        else if (asi.InterfaceType == INTERFACE_TYPE::SATA)
            interfaceTypeStr = "SATA ";
        else if (asi.InterfaceType == INTERFACE_TYPE::NVME)
            interfaceTypeStr = "NVME ";
        else
            interfaceTypeStr = "UNKNOWN ";

        std::cout << "\t" << interfaceTypeStr << asi.DriveMap << (asi.BootFromDisk ? " System" : "") << std::endl;
        std::cout << "\tModel          " << asi.Model << std::endl;
        std::cout << "\tFirmware       " << asi.FirmwareRev << std::endl;
        std::cout << "\tSerialNumber   " << asi.SerialNumber << std::endl;
        std::cout << "\tCommandType    " << commandTypeString[static_cast<int>(asi.CommandType)] << std::endl;
        std::cout << "\tDataSource     " << dataSourceTypeString[static_cast<int>(asi.DataSource)] << std::endl;
        std::cout << "------------------------------------------------------" << std::endl << std::endl;
	}
}
#endif

int main(int argc, char *argv[])
{
	CIDFinder &drive = CIDFinder::get();

	drive.init();

#if USE_DEBUG
	drive.dump();
#endif

	std::cout << "\tSerialNumber   " << drive.getSerialNumber() << std::endl;
	system("pause");

	return 0;
}