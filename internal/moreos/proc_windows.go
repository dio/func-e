// Copyright 2021 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package moreos

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	pe "github.com/Velocidex/go-pe"
)

const (
	exe = ".exe"
	// from WinError.h, but not defined for some reason in types_windows.go
	errorInvalidParameter = 87

	// The MZ signature is a signature used by the MS-DOS relocatbale 16-bit EXE format. The signature
	// is 0x5a4d (https://dev.to/wireless90/getting-the-windows-pe-internals-kka).
	IMAGE_DOS_SIGNATURE = 0x5a4d
	// In a valid PE file, the Signature field is set to the value 0x00004550, which in ASCII is
	// "PE00". A #define, IMAGE_NT_SIGNATURE, is defined for this value
	// https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail.
	IMAGE_NT_SIGNATURE = 0x4550
	// To make sure the file is not a .dll. https://docs.microsoft.com/en-us/windows/win32/debug/pe-format.
	IMAGE_FILE_DLL = 0x2000
	// The file is an executable image for 32-bit archithecture.
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32.
	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
	// The file is an executable image for 64-bit archithecture.
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
)

func processGroupAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP, // Stop Ctrl-Break propagation to allow shutdown-hooks
	}
}

// interrupt contains signal_windows_test.go sendCtrlBreak() as there's no main source with the same.
func interrupt(p *os.Process) error {
	pid := p.Pid
	d, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return errorInterrupting(pid, err)
	}
	proc, err := d.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return errorInterrupting(pid, err)
	}
	r, _, err := proc.Call(syscall.CTRL_BREAK_EVENT, uintptr(pid))
	if r == 0 { // because err != nil on success "The operation completed successfully"
		return errorInterrupting(pid, err)
	}
	return nil
}

func errorInterrupting(pid int, err error) error {
	return fmt.Errorf("couldn't Interrupt pid(%d): %w", pid, err)
}

// ensureProcessDone attempts to work around flakey logic in os.Process Wait on Windows. This code block should be
// revisited if https://golang.org/issue/25965 is solved.
func ensureProcessDone(p *os.Process) error {
	// Process.handle is not exported. Lookup the process again, using logic similar to exec_windows/findProcess()
	const da = syscall.STANDARD_RIGHTS_READ | syscall.PROCESS_TERMINATE |
		syscall.PROCESS_QUERY_INFORMATION | syscall.SYNCHRONIZE
	h, e := syscall.OpenProcess(da, true, uint32(p.Pid))
	if e != nil {
		if errno, ok := e.(syscall.Errno); ok && uintptr(errno) == errorInvalidParameter {
			return nil // don't error if the process isn't around anymore
		}
		return os.NewSyscallError("OpenProcess", e)
	}
	defer syscall.CloseHandle(h) //nolint:errcheck

	// Try to wait for the process to close naturally first, using logic from exec_windows/findProcess()
	// Difference here, is we are waiting 100ms not infinite. If there's a timeout, we kill the proc.
	s, e := syscall.WaitForSingleObject(h, 100)
	switch s {
	case syscall.WAIT_OBJECT_0:
		return nil // process is no longer around
	case syscall.WAIT_TIMEOUT:
		return syscall.TerminateProcess(h, uint32(0)) // kill, but don't effect the exit code
	case syscall.WAIT_FAILED:
		return os.NewSyscallError("WaitForSingleObject", e)
	default:
		return errors.New("os: unexpected result from WaitForSingleObject")
	}
}

func isExecutable(f os.FileInfo) bool { // In windows, we cannot read execute bit
	fd, err := os.Open(f.Name())
	if err != nil {
		return false
	}

	profile := pe.NewPeProfile()
	dosHeader := profile.IMAGE_DOS_HEADER(fd, 0)
	// Check if we have MZ signature.
	if dosHeader.E_magic() != IMAGE_DOS_SIGNATURE {
		return false
	}

	ntHeader := dosHeader.NTHeader()
	// The file needs to be a valid PE file.
	if ntHeader.Signature() != IMAGE_NT_SIGNATURE {
		return false
	}

	// Make sure the file is not a .dll file.
	if ntHeader.FileHeader().Profile.Off_IMAGE_IMPORT_DESCRIPTOR_Characteristics&IMAGE_FILE_DLL != 0 {
		return false
	}

	// Check architecture specific magic optional header.
	switch ntHeader.FileHeader().Machine().Name {
	case "IMAGE_FILE_MACHINE_I386":
		return ntHeader.OptionalHeader().Magic() == IMAGE_NT_OPTIONAL_HDR32_MAGIC
	case "IMAGE_FILE_MACHINE_IA64":
	case "IMAGE_FILE_MACHINE_AMD64":
		return ntHeader.OptionalHeader().Magic() == IMAGE_NT_OPTIONAL_HDR64_MAGIC
	default:
		// TODO: Add a check for IMAGE_FILE_MACHINE_ARM.
		return false
	}

	return strings.HasSuffix(f.Name(), ".exe")
}
