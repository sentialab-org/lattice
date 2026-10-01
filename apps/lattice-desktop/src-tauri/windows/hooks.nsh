!macro NSIS_HOOK_PREINSTALL
  IfFileExists "$INSTDIR\lattice-node.exe" 0 lattice_preinstall_done
  ExecWait '"$INSTDIR\lattice-node.exe" --stop-service'
  Delete "$INSTDIR\lattice-node.exe"
  lattice_preinstall_done:
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ExecWait '"$INSTDIR\lattice-node.exe" --install-service' $0
  IntCmp $0 0 lattice_postinstall_done
  MessageBox MB_ICONSTOP|MB_OK "Lattice Node service installation failed with exit code $0."
  Abort
  lattice_postinstall_done:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  IfFileExists "$INSTDIR\lattice-node.exe" 0 lattice_preuninstall_done
  ExecWait '"$INSTDIR\lattice-node.exe" --uninstall-service'
  lattice_preuninstall_done:
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
!macroend
