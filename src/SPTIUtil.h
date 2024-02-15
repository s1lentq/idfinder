#pragma once

#include <string>

// From Driver Development Kit

#define	FILE_DEVICE_SCSI							0x0000001b
#define	IOCTL_SCSI_MINIPORT_IDENTIFY				((FILE_DEVICE_SCSI << 16) + 0x0501)
#define	IOCTL_SCSI_MINIPORT_READ_SMART_ATTRIBS		((FILE_DEVICE_SCSI << 16) + 0x0502)
#define IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS	((FILE_DEVICE_SCSI << 16) + 0x0503)
#define IOCTL_SCSI_MINIPORT_ENABLE_SMART			((FILE_DEVICE_SCSI << 16) + 0x0504)
#define IOCTL_SCSI_MINIPORT_DISABLE_SMART			((FILE_DEVICE_SCSI << 16) + 0x0505)

#define IOCTL_SCSI_BASE					FILE_DEVICE_CONTROLLER
#define IOCTL_SCSI_PASS_THROUGH			CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//
// Define values for pass-through DataIn field
//
#define SCSI_IOCTL_DATA_OUT				0
#define SCSI_IOCTL_DATA_IN				1
#define SCSI_IOCTL_DATA_UNSPECIFIED		2

//
// Define the SCSI pass through structure
//
typedef struct _SCSI_PASS_THROUGH
{
	USHORT Length;
	UCHAR ScsiStatus;
	UCHAR PathId;
	UCHAR TargetId;
	UCHAR Lun;
	UCHAR CdbLength;
	UCHAR SenseInfoLength;
	UCHAR DataIn;
	ULONG DataTransferLength;
	ULONG TimeOutValue;
	ULONG_PTR DataBufferOffset;
	ULONG SenseInfoOffset;
	UCHAR Cdb[16];
} SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS
{
	SCSI_PASS_THROUGH Spt;
	ULONG				Filler;			// realign buffers to double word boundary
	UCHAR				SenseBuf[32];
	UCHAR				DataBuf[4096];
} SCSI_PASS_THROUGH_WITH_BUFFERS, *PSCSI_PASS_THROUGH_WITH_BUFFERS;

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS24
{
	SCSI_PASS_THROUGH	Spt;
	UCHAR				SenseBuf[24];
	UCHAR				DataBuf[4096];
} SCSI_PASS_THROUGH_WITH_BUFFERS24, *PSCSI_PASS_THROUGH_WITH_BUFFERS24;

namespace StrUtil {
	inline std::string trim(const std::string &str, const std::string chars = " \n\r\t") {
		size_t first = str.find_first_not_of(chars);
		if (first == std::string::npos) return str;
		return str.substr(first, (str.find_last_not_of(chars) - first + 1));
	}

	inline void change_byte_order(std::string &str) {
		for (size_t i = 0; i < str.size(); i += 2) {
			std::swap(str[i], str[i + 1]);
		}
	}

	std::string ws2s(const std::wstring &in) {
		int needbytes = WideCharToMultiByte(CP_UTF8, 0, &in[0], (int)in.size(), NULL, 0, NULL, NULL);
		std::string out(needbytes, 0);
		WideCharToMultiByte(CP_UTF8, 0, &in[0], (int)in.size(), &out[0], needbytes, NULL, NULL);
		return out;
	}

	std::wstring s2ws(const std::string &in) {
		int needbytes = MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), NULL, 0);
		std::wstring out(needbytes, 0);
		MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), &out[0], needbytes);
		return out;
	}
}
