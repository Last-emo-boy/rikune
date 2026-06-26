import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { DatabaseManager } from '../database.js'
import type { PolicyGuard } from '../policy-guard.js'
import { logWarning } from '../logger.js'

export const MAX_SAMPLE_SIZE = 500 * 1024 * 1024

export interface FinalizeSampleInput {
  data: Buffer
  filename?: string
  source?: string
  auditOperation?: string
}

export interface FinalizeSampleResult {
  sample_id: string
  size: number
  file_type: string
  existed?: boolean
  sha256: string
  md5: string
}

function computeSHA256(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

function computeMD5(data: Buffer): string {
  return crypto.createHash('md5').update(data).digest('hex')
}

function normalizeFileExtension(filename?: string): string | null {
  if (!filename) return null
  const basename = path.posix.basename(filename.replace(/\\/g, '/')).trim().toLowerCase()
  if (!basename.includes('.')) return null
  if (basename.endsWith('.safetensors.index.json')) return 'safetensors.index.json'
  if (basename.endsWith('.abi.json')) return 'abi.json'
  if (basename.endsWith('.appimage')) return 'appimage'
  return basename.slice(basename.lastIndexOf('.') + 1)
}

function normalizeFileBasename(filename?: string): string {
  if (!filename) return ''
  return path.posix.basename(filename.replace(/\\/g, '/')).trim().toLowerCase()
}

function detectZipFileType(data: Buffer, extension: string | null): string {
  switch (extension) {
    case 'apk':
      return 'APK'
    case 'aab':
      return 'AAB'
    case 'apks':
      return 'APKS'
    case 'xapk':
      return 'XAPK'
    case 'ipa':
      return 'IPA'
    case 'aar':
      return 'AAR'
    case 'jar':
      return 'JAR'
    case 'war':
      return 'WAR'
    case 'jmod':
      return 'JMOD'
    case 'msix':
      return 'MSIX'
    case 'appx':
      return 'APPX'
    case 'nupkg':
      return 'NUPKG'
    case 'npz':
      return 'NumPy-NPZ'
    case 'pt':
    case 'pth':
    case 'ckpt':
      return 'PyTorch-Checkpoint'
    default:
      break
  }

  const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  if (
    preview.includes('data.pkl') &&
    (preview.includes('archive/') || preview.includes('version'))
  ) {
    return 'PyTorch-Checkpoint'
  }
  if (preview.includes('.npy')) return 'NumPy-NPZ'
  if (preview.includes('oci-layout')) return 'OCI-Image'
  if (preview.includes('manifest.json') && preview.includes('layer')) return 'Docker-Image'
  if (preview.includes('Payload/') && preview.includes('.app/')) return 'IPA'
  if (preview.includes('AndroidManifest.xml') && preview.includes('classes.dex')) return 'APK'
  if (preview.includes('AndroidManifest.xml') && preview.includes('classes.jar')) return 'AAR'
  if (preview.includes('AppxManifest.xml')) return 'APPX'
  if (preview.includes('.nuspec')) return 'NUPKG'
  if (preview.includes('META-INF/MANIFEST.MF')) return 'JAR'
  return 'ZIP'
}

export function detectFileType(data: Buffer, filename?: string): string {
  const extension = normalizeFileExtension(filename)
  const basename = normalizeFileBasename(filename)

  if (
    data.length >= 4 &&
    data[0] === 0x42 &&
    data[1] === 0x43 &&
    data[2] === 0xc0 &&
    data[3] === 0xde
  ) {
    return 'LLVM-Bitcode'
  }

  if (data.length >= 20 && data.readUInt32LE(0) === 0x0b17c0de) {
    return 'LLVM-Bitcode-Wrapper'
  }

  if (
    data.length >= 4 &&
    (data.readUInt32LE(0) === 0x07230203 || data.readUInt32BE(0) === 0x07230203)
  ) {
    return 'SPIR-V'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'DXBC') {
    return 'DXContainer'
  }

  if (data.length >= 4 && ['MTLB', 'MTLL'].includes(data.subarray(0, 4).toString('ascii'))) {
    return 'Metal-Metallib'
  }

  if (
    data.length >= 24 &&
    ((data[0] === 0x9f && data[1] === 0xeb) || (data[0] === 0xeb && data[1] === 0x9f)) &&
    data[2] === 1
  ) {
    if (extension === 'ext' && basename.endsWith('.btf.ext')) return 'BTF-Ext'
    return 'BTF'
  }

  if (
    data.length >= 8 &&
    (data.readBigUInt64LE(0) === 0x8b47f2a4d7623eebn ||
      data.readBigUInt64BE(0) === 0x8b47f2a4d7623eebn)
  ) {
    return 'CTF-Archive'
  }

  if (data.length >= 2 && (data.readUInt16LE(0) === 0xdff2 || data.readUInt16BE(0) === 0xdff2)) {
    return 'CTF'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'GGUF') {
    return 'GGUF'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii').toLowerCase() === 'ggml') {
    return 'GGML'
  }

  if (data.length >= 8 && data[0] === 0x93 && data.subarray(1, 6).toString('ascii') === 'NUMPY') {
    return 'NumPy-NPY'
  }

  if (data.length >= 8 && data.subarray(4, 8).toString('ascii') === 'TFL3') {
    return 'TFLite-Model'
  }

  if (data.length >= 8) {
    const headerLength = Number(data.readBigUInt64LE(0))
    if (
      Number.isSafeInteger(headerLength) &&
      headerLength > 1 &&
      headerLength <= Math.max(data.length - 8, 1) &&
      data[8] === 0x7b
    ) {
      return 'SafeTensors'
    }
  }

  if (
    data.length >= 1 &&
    data[0] === 0x80 &&
    ['pkl', 'pickle', 'pt', 'pth', 'ckpt'].includes(extension ?? '')
  ) {
    return ['pt', 'pth', 'ckpt'].includes(extension ?? '') ? 'PyTorch-Pickle' : 'Pickle'
  }

  if (extension === 'safetensors' || extension === 'safetensors.index.json') {
    return 'SafeTensors'
  }

  if (extension === 'gguf') {
    return 'GGUF'
  }

  if (extension === 'ggml') {
    return 'GGML'
  }

  if (extension === 'onnx') {
    return 'ONNX-Model'
  }

  if (extension === 'tflite') {
    return 'TFLite-Model'
  }

  if (extension === 'npy') {
    return 'NumPy-NPY'
  }

  if (extension === 'spv' || extension === 'spirv') {
    return 'SPIR-V'
  }

  if (extension === 'dxil') {
    return 'DXIL-Container'
  }

  if (extension === 'dxbc' || extension === 'cso') {
    return 'DXBC-Container'
  }

  if (extension === 'metallib') {
    return 'Metal-Metallib'
  }

  if (extension === 'wgsl') {
    return 'WGSL'
  }

  if (extension === 'mobileprovision') {
    return 'MobileProvision'
  }

  if (extension === 'swiftmodule') {
    return 'SwiftModule'
  }

  if (extension === 'swiftinterface') {
    return 'SwiftInterface'
  }

  if (extension === 'swiftdoc') {
    return 'SwiftDoc'
  }

  if (extension === 'abi.json') {
    return 'Swift-ABI'
  }

  if (extension === 'dsym' || basename.endsWith('.dsym')) {
    return 'dSYM'
  }

  if (extension === 'dwo') {
    return 'DWO'
  }

  if (extension === 'dwp') {
    return 'DWP'
  }

  if (extension === 'debug') {
    return 'DWARF-Debug'
  }

  if (extension === 'ctf') {
    return 'CTF'
  }

  if (extension === 'app') {
    return 'App-Bundle'
  }

  if (extension === 'ptx') {
    return 'CUDA-PTX'
  }

  if (extension === 'cubin') {
    return 'CUDA-CUBIN'
  }

  if (extension === 'fatbin') {
    return 'CUDA-Fatbin'
  }

  const firmwarePreview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
  const firmwareVolumeHeaderOffset = firmwarePreview.indexOf('_FVH')
  const firmwareLikeExtension = [
    'fd',
    'rom',
    'bin',
    'cap',
    'capsule',
    'efi',
    'dxe',
    'pei',
    'smm',
    'te',
  ].includes(extension ?? '')
  if (
    firmwareVolumeHeaderOffset >= 0 &&
    (firmwareLikeExtension || firmwareVolumeHeaderOffset < 0x10000)
  ) {
    return 'UEFI-Firmware-Volume'
  }

  if (data.length >= 2 && data[0] === 0x56 && data[1] === 0x5a) {
    if (['te', 'efi', 'dxe', 'smm', 'pei'].includes(extension ?? '')) return 'UEFI-TE'
  }

  if (['cap', 'capsule'].includes(extension ?? '')) {
    return 'UEFI-Capsule'
  }

  if (extension === 'bpf' || extension === 'ebpf') {
    if (
      data.length >= 4 &&
      data[0] === 0x7f &&
      data[1] === 0x45 &&
      data[2] === 0x4c &&
      data[3] === 0x46
    ) {
      return 'eBPF-ELF'
    }
    return 'eBPF-Bytecode'
  }

  if (['syscall', 'syscallstub', 'ntdllstub', 'stub'].includes(extension ?? '')) {
    return 'Syscall-Stub'
  }

  if (['sc', 'shellcode'].includes(extension ?? '')) {
    return 'Raw-Shellcode'
  }

  if (extension === 'framework') {
    return 'Framework'
  }

  if (extension === 'xcframework') {
    return 'XCFramework'
  }

  if (
    basename === 'global-metadata.dat' ||
    (data.length >= 4 &&
      data[0] === 0xfa &&
      data[1] === 0xb1 &&
      data[2] === 0x1b &&
      data[3] === 0xaf)
  ) {
    return 'Unity-Metadata'
  }

  const looksLikeBinaryContainer =
    (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) ||
    (data.length >= 4 &&
      data[0] === 0x7f &&
      data[1] === 0x45 &&
      data[2] === 0x4c &&
      data[3] === 0x46) ||
    (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) ||
    (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n')

  if (data.length > 0 && !looksLikeBinaryContainer) {
    const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
    if (
      /^\s*\.version\s+[0-9]+(?:\.[0-9]+)?/m.test(preview) &&
      /^\s*\.target\s+.*\b(?:sm|compute)_[0-9]{2,3}[a-z]?\b/m.test(preview) &&
      /^\s*(?:\.visible\s+)?\.entry\s+[A-Za-z_$][A-Za-z0-9_.$]*/m.test(preview)
    ) {
      return 'CUDA-PTX'
    }
  }

  if (
    data.length >= 6 &&
    data[0] === 0x37 &&
    data[1] === 0x7a &&
    data[2] === 0xbc &&
    data[3] === 0xaf &&
    data[4] === 0x27 &&
    data[5] === 0x1c
  ) {
    return '7z'
  }

  if (data.length >= 7 && data.subarray(0, 4).toString('ascii') === 'Rar!') {
    return 'RAR'
  }

  if (
    data.length >= 6 &&
    data[0] === 0xfd &&
    data[1] === 0x37 &&
    data[2] === 0x7a &&
    data[3] === 0x58 &&
    data[4] === 0x5a &&
    data[5] === 0x00
  ) {
    return 'XZ'
  }

  if (
    data.length >= 4 &&
    data[0] === 0x28 &&
    data[1] === 0xb5 &&
    data[2] === 0x2f &&
    data[3] === 0xfd
  ) {
    return 'ZSTD'
  }

  if (data.length >= 262 && data.subarray(257, 262).toString('ascii') === 'ustar') {
    const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
    if (preview.includes('oci-layout')) return 'OCI-Image'
    if (preview.includes('manifest.json') && preview.includes('layer')) return 'Docker-Image'
    return 'TAR'
  }

  if (data.length >= 0x8006 && data.subarray(0x8001, 0x8006).toString('ascii') === 'CD001') {
    return 'ISO'
  }

  if (
    data.length >= 24 &&
    data.subarray(0, 24).toString('ascii').startsWith('Microsoft C/C++ MSF')
  ) {
    return 'PDB'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'MSCF') {
    return 'CAB'
  }

  if (data.length >= 4 && data.readUInt32BE(0) === 0x27051956) {
    return 'U-Boot-uImage'
  }

  if (data.length >= 4 && data.readUInt32BE(0) === 0xd00dfeed) {
    return extension === 'itb' ? 'FIT-Image' : 'DTB'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'hsqs') {
    return 'SquashFS'
  }

  if (data.length >= 4 && data.readUInt32LE(0) === 0x28cd3d45) {
    return 'CramFS'
  }

  if (
    data.length >= 2 &&
    ((data[0] === 0x85 && data[1] === 0x19) || (data[0] === 0x19 && data[1] === 0x85))
  ) {
    return 'JFFS2'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'UBI#') {
    return 'UBI'
  }

  if (data.length >= 4 && data.readUInt32LE(0) === 0x06101831) {
    return 'UBIFS'
  }

  if (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '-rom1fs-') {
    return 'ROMFS'
  }

  if (
    data.length >= 6 &&
    ['070701', '070702', '070707'].includes(data.subarray(0, 6).toString('ascii'))
  ) {
    return 'CPIO'
  }

  if (
    data.length >= 8 &&
    data[0] === 0xd0 &&
    data[1] === 0xcf &&
    data[2] === 0x11 &&
    data[3] === 0xe0 &&
    data[4] === 0xa1 &&
    data[5] === 0xb1 &&
    data[6] === 0x1a &&
    data[7] === 0xe1 &&
    ['msi', 'msp', 'msm'].includes(extension ?? '')
  ) {
    return 'MSI'
  }

  if (data.length >= 2 && data[0] === 0x4d && data[1] === 0x5a) {
    const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
    if (basename === 'gameassembly.dll' || preview.includes('il2cpp')) return 'IL2CPP'
    if (extension === 'efi') return 'EFI'
    if (extension === 'sys') return 'SYS'
    if (extension === 'winmd') return 'WinMD'
    if (preview.includes('BSJB') || preview.toLowerCase().includes('mscoree.dll')) {
      return 'PE-CLR'
    }
    if (preview.includes('NullsoftInst')) return 'NSIS'
    if (preview.includes('Inno Setup')) return 'Inno'
    return 'PE'
  }

  if (
    data.length >= 11 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46 &&
    (extension === 'appimage' || data.subarray(8, 10).toString('ascii') === 'AI')
  ) {
    return 'AppImage'
  }

  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46 &&
    basename.includes('il2cpp')
  ) {
    return 'IL2CPP'
  }

  if (
    data.length >= 4 &&
    data[0] === 0x7f &&
    data[1] === 0x45 &&
    data[2] === 0x4c &&
    data[3] === 0x46
  ) {
    const preview = data.subarray(0, Math.min(data.length, 1024 * 1024)).toString('latin1')
    const endian = data[5] === 2 ? 'be' : 'le'
    const readUInt16 = (offset: number) =>
      endian === 'be' ? data.readUInt16BE(offset) : data.readUInt16LE(offset)
    const elfType = data.length >= 18 ? readUInt16(16) : 0
    const elfMachine = data.length >= 20 ? readUInt16(18) : 0
    if (elfMachine === 190) return 'CUDA-CUBIN'
    if (elfMachine === 247) return 'eBPF-ELF'
    if (extension === 'ko' || basename.endsWith('.ko') || preview.includes('vermagic=')) {
      return 'Linux-Kernel-Module'
    }
    if (elfType === 1) return 'ELF-Object'
    if (elfType === 3 && ['so', 'dylib'].includes(extension ?? '')) return 'ELF-SO'
    if (elfType === 4 || extension === 'core') return 'ELF-Core'
    if (elfType === 2) return 'ELF-Executable'
    return 'ELF'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'dex\n') {
    return 'DEX'
  }

  if (
    data.length >= 4 &&
    data[0] === 0xca &&
    data[1] === 0xfe &&
    data[2] === 0xba &&
    data[3] === 0xbe &&
    extension === 'class'
  ) {
    return 'CLASS'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'vdex') {
    return 'VDEX'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'oat\n') {
    return 'OAT'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'dey\n') {
    return 'ODEX'
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'art\n') {
    return 'ART'
  }

  if (
    data.length >= 8 &&
    data[0] === 0x00 &&
    data[1] === 0x61 &&
    data[2] === 0x73 &&
    data[3] === 0x6d
  ) {
    if (data.readUInt16LE(6) === 1) return 'WASM-Component'
    return 'WASM'
  }

  if (
    data.length >= 4 &&
    data[0] === 0x1b &&
    data[1] === 0x4c &&
    data[2] === 0x75 &&
    data[3] === 0x61
  ) {
    return 'Lua-Bytecode'
  }

  if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b) {
    return detectZipFileType(data, extension)
  }

  if (data.length >= 8 && data.subarray(0, 8).toString('ascii') === '!<arch>\n') {
    const preview = data.subarray(8, Math.min(data.length, 4096)).toString('latin1')
    if (extension === 'lib') return 'COFF-LIB'
    if (extension === 'a') return 'AR-Static-Lib'
    if (preview.includes('debian-binary')) return 'DEB'
    return 'AR'
  }

  if (
    data.length >= 4 &&
    data[0] === 0xed &&
    data[1] === 0xab &&
    data[2] === 0xee &&
    data[3] === 0xdb
  ) {
    return 'RPM'
  }

  if (data.length >= 4) {
    const magic32 = data.readUInt32BE(0)
    // Mach-O 32-bit, 64-bit, and fat binary magic numbers (both endiannesses)
    if (
      magic32 === 0xfeedface ||
      magic32 === 0xfeedfacf ||
      magic32 === 0xcefaedfe ||
      magic32 === 0xcffaedfe
    ) {
      const fileType =
        data.length >= 16 && (magic32 === 0xfeedface || magic32 === 0xfeedfacf)
          ? data.readUInt32BE(12)
          : data.length >= 16
            ? data.readUInt32LE(12)
            : 0
      if (fileType === 1 || extension === 'o') return 'Mach-O-Object'
      return 'Mach-O'
    }
    if (magic32 === 0xcafebabe || magic32 === 0xbebafeca) {
      return 'Mach-O-Fat'
    }
  }

  if (data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'xar!') {
    return 'PKG'
  }

  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b && extension === 'apk') {
    return 'APK-Alpine'
  }

  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) {
    return 'GZ'
  }

  if (
    data.length >= 512 &&
    data.subarray(data.length - 512, data.length - 508).toString('ascii') === 'koly'
  ) {
    return 'DMG'
  }

  switch (extension) {
    case 'js':
      return 'JavaScript'
    case 'mjs':
      return 'MJS'
    case 'cjs':
      return 'CJS'
    case 'ts':
    case 'tsx':
      return 'TypeScript'
    case 'map':
      return 'Source-Map'
    case 'html':
    case 'htm':
      return 'HTML'
    case 'wat':
      return 'WAT'
    case 'bc':
      return 'LLVM-Bitcode'
    case 'll':
      return 'LLVM-IR'
    case 'spv':
    case 'spirv':
      return 'SPIR-V'
    case 'dxil':
      return 'DXIL-Container'
    case 'dxbc':
    case 'cso':
      return 'DXBC-Container'
    case 'wgsl':
      return 'WGSL'
    case 'metallib':
      return 'Metal-Metallib'
    case 'onnx':
      return 'ONNX-Model'
    case 'tflite':
      return 'TFLite-Model'
    case 'safetensors':
    case 'safetensors.index.json':
      return 'SafeTensors'
    case 'gguf':
      return 'GGUF'
    case 'ggml':
      return 'GGML'
    case 'pt':
    case 'pth':
    case 'ckpt':
      return 'PyTorch-Checkpoint'
    case 'pkl':
    case 'pickle':
      return 'Pickle'
    case 'npy':
      return 'NumPy-NPY'
    case 'npz':
      return 'NumPy-NPZ'
    case 'deb':
      return 'DEB'
    case 'rpm':
      return 'RPM'
    case 'apk':
      return 'APK'
    case 'snap':
      return 'Snap'
    case 'flatpak':
      return 'Flatpak'
    case 'zip':
      return 'ZIP'
    case '7z':
      return '7z'
    case 'rar':
      return 'RAR'
    case 'tar':
      return 'TAR'
    case 'gz':
    case 'tgz':
      return 'GZ'
    case 'xz':
      return 'XZ'
    case 'zst':
    case 'zstd':
      return 'ZSTD'
    case 'iso':
      return 'ISO'
    case 'oci':
      return 'OCI-Image'
    case 'docker':
      return 'Docker-Image'
    case 'dmg':
      return 'DMG'
    case 'pkg':
      return 'PKG'
    case 'mobileprovision':
      return 'MobileProvision'
    case 'swiftmodule':
      return 'SwiftModule'
    case 'swiftinterface':
      return 'SwiftInterface'
    case 'swiftdoc':
      return 'SwiftDoc'
    case 'abi.json':
      return 'Swift-ABI'
    case 'app':
      return 'App-Bundle'
    case 'framework':
      return 'Framework'
    case 'xcframework':
      return 'XCFramework'
    case 'dsym':
      return 'dSYM'
    case 'dwo':
      return 'DWO'
    case 'dwp':
      return 'DWP'
    case 'debug':
      return 'DWARF-Debug'
    case 'ctf':
      return 'CTF'
    case 'msi':
    case 'msp':
    case 'msm':
      return 'MSI'
    case 'msix':
      return 'MSIX'
    case 'appx':
      return 'APPX'
    case 'cab':
      return 'CAB'
    case 'nsis':
      return 'NSIS'
    case 'inno':
      return 'Inno'
    case 'pdb':
      return 'PDB'
    case 'obj':
      return 'COFF'
    case 'lib':
      return 'COFF-LIB'
    case 'o':
      return 'Object'
    case 'a':
      return 'AR-Static-Lib'
    case 'ko':
      return 'Linux-Kernel-Module'
    case 'nupkg':
      return 'NUPKG'
    case 'winmd':
      return 'WinMD'
    case 'tlb':
    case 'olb':
      return 'TypeLib'
    case 'idl':
      return 'IDL'
    case 'dll':
    case 'exe':
      if (basename === 'gameassembly.dll') return 'IL2CPP'
      return 'PE'
    case 'efi':
      return 'EFI'
    case 'dxe':
    case 'pei':
    case 'smm':
    case 'te':
      return 'UEFI-Module'
    case 'cap':
    case 'capsule':
      return 'UEFI-Capsule'
    case 'fd':
      return 'UEFI-Firmware'
    case 'sys':
      return 'SYS'
    case 'ipa':
      return 'IPA'
    case 'wasm':
      if (basename.endsWith('.component.wasm') || basename.endsWith('.wit.wasm')) {
        return 'WASM-Component'
      }
      return 'WASM'
    case 'ptx':
      return 'CUDA-PTX'
    case 'cubin':
      return 'CUDA-CUBIN'
    case 'fatbin':
      return 'CUDA-Fatbin'
    case 'pyc':
      return 'PYC'
    case 'luac':
      return 'Lua-Bytecode'
    case 'jsc':
    case 'blob':
      return 'V8-Cache'
    case 'class':
      return 'CLASS'
    case 'jar':
      return 'JAR'
    case 'war':
      return 'WAR'
    case 'jmod':
      return 'JMOD'
    case 'dex':
      return 'DEX'
    case 'vdex':
      return 'VDEX'
    case 'oat':
      return 'OAT'
    case 'odex':
      return 'ODEX'
    case 'art':
      return 'ART'
    case 'aab':
      return 'AAB'
    case 'apks':
      return 'APKS'
    case 'xapk':
      return 'XAPK'
    case 'aar':
      return 'AAR'
    case 'unity':
      return 'Unity'
    case 'uimage':
    case 'img':
      return 'Firmware'
    case 'fit':
    case 'itb':
      return 'FIT-Image'
    case 'dtb':
      return 'DTB'
    case 'cpio':
      return 'CPIO'
    case 'squashfs':
      return 'SquashFS'
    case 'cramfs':
      return 'CramFS'
    case 'jffs2':
      return 'JFFS2'
    case 'ubi':
      return 'UBI'
    case 'ubifs':
      return 'UBIFS'
    case 'romfs':
      return 'ROMFS'
    default:
      break
  }

  return 'unknown'
}

function normalizeFilename(filename?: string): string {
  const candidate = typeof filename === 'string' ? filename.replace(/\\/g, '/') : ''
  const basename = path.posix.basename(candidate || 'sample.bin').trim()
  return basename.length > 0 ? basename : 'sample.bin'
}

export class SampleFinalizationService {
  constructor(
    private readonly workspaceManager: WorkspaceManager,
    private readonly database: DatabaseManager,
    private readonly policyGuard: PolicyGuard
  ) {}

  async finalizeBuffer(input: FinalizeSampleInput): Promise<FinalizeSampleResult> {
    if (input.data.length > MAX_SAMPLE_SIZE) {
      throw new Error(
        `Sample size ${input.data.length} bytes exceeds maximum limit of ${MAX_SAMPLE_SIZE} bytes (500MB)`
      )
    }

    const sha256 = computeSHA256(input.data)
    const md5 = computeMD5(input.data)
    const sampleId = `sha256:${sha256}`
    const source = input.source || 'upload'
    const filename = normalizeFilename(input.filename)
    const existingSample = this.database.findSampleBySha256(sha256)

    if (existingSample) {
      await this.policyGuard.auditLog({
        timestamp: new Date().toISOString(),
        operation: input.auditOperation || 'sample.ingest',
        sampleId: existingSample.id,
        decision: 'allow',
        reason: 'Sample already exists (SHA256 match)',
        metadata: {
          size: input.data.length,
          source,
          existed: true,
        },
      })

      return {
        sample_id: existingSample.id,
        size: existingSample.size,
        file_type: existingSample.file_type || 'unknown',
        existed: true,
        sha256,
        md5,
      }
    }

    const workspace = await this.workspaceManager.createWorkspace(sampleId)
    const samplePath = path.join(workspace.original, filename)
    fs.writeFileSync(samplePath, input.data)

    try {
      fs.chmodSync(samplePath, 0o444)
    } catch (error) {
      logWarning('Failed to set file permissions', {
        path: samplePath,
        error: (error as Error).message,
      })
    }

    const fileType = detectFileType(input.data, filename)
    const sample = {
      id: sampleId,
      sha256,
      md5,
      size: input.data.length,
      file_type: fileType,
      created_at: new Date().toISOString(),
      source,
    }

    try {
      this.database.insertSample(sample)
    } catch (error: any) {
      if (
        error.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
        error.message?.includes('UNIQUE constraint')
      ) {
        const concurrentSample = this.database.findSampleBySha256(sha256)
        if (concurrentSample) {
          await this.policyGuard.auditLog({
            timestamp: new Date().toISOString(),
            operation: input.auditOperation || 'sample.ingest',
            sampleId: concurrentSample.id,
            decision: 'allow',
            reason: 'Sample already exists (concurrent insert race condition)',
            metadata: {
              size: input.data.length,
              source,
              existed: true,
            },
          })

          return {
            sample_id: concurrentSample.id,
            size: concurrentSample.size,
            file_type: concurrentSample.file_type || 'unknown',
            existed: true,
            sha256,
            md5,
          }
        }
      }

      throw error
    }

    await this.policyGuard.auditLog({
      timestamp: new Date().toISOString(),
      operation: input.auditOperation || 'sample.ingest',
      sampleId: sample.id,
      decision: 'allow',
      metadata: {
        size: input.data.length,
        source,
        file_type: fileType,
      },
    })

    return {
      sample_id: sampleId,
      size: input.data.length,
      file_type: fileType,
      sha256,
      md5,
    }
  }
}

export function createSampleFinalizationService(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  policyGuard: PolicyGuard
): SampleFinalizationService {
  return new SampleFinalizationService(workspaceManager, database, policyGuard)
}
