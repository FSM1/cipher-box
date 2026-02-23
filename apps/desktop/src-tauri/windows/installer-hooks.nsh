; CipherBox NSIS Installer Hooks
; Bundled WinFsp driver installation
;
; WinFsp (Windows File System Proxy) is required for the virtual filesystem
; that mounts the encrypted vault at ~/CipherBox.
;
; The WinFsp MSI is bundled in the installer resources and installed silently
; during CipherBox setup if not already present on the system.

!macro NSIS_HOOK_PREINSTALL
  ; WinFsp install moved to POSTINSTALL — $INSTDIR is not populated yet during PREINSTALL.
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Check if WinFsp is already installed via registry
  ReadRegStr $0 HKLM "SOFTWARE\WinFsp" "InstallDir"
  StrCmp $0 "" 0 winfsp_installed

  ; WinFsp not installed -- install it silently
  DetailPrint "Installing WinFsp filesystem driver..."
  ExecWait '"msiexec" /i "$INSTDIR\resources\winfsp-2.1.25156.msi" /qn INSTALLLEVEL=1000' $0
  StrCmp $0 "0" winfsp_installed
    MessageBox MB_OK|MB_ICONEXCLAMATION "WinFsp installation failed (exit code: $0). CipherBox requires WinFsp for the virtual filesystem. You can install it manually from https://winfsp.dev"
  winfsp_installed:
    DetailPrint "WinFsp filesystem driver is installed."
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Don't uninstall WinFsp -- other apps may use it.
  ; Users can uninstall WinFsp manually via Add/Remove Programs if desired.
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Clean up CipherBox mount point if it still exists
  RMDir "$PROFILE\CipherBox"
!macroend
