import { describe, expect, test } from '@jest/globals'
import {
  ANALYZER_WSL_FILESYSTEM_ERROR,
  ANALYZER_WSL2_REQUIRED_ERROR,
  assertSupportedAnalyzerFilesystem,
  parseLinuxMountInfo,
} from '../../src/analyzer-filesystem.js'

const WSL_MOUNT_INFO = [
  '24 1 8:1 / / rw,relatime - ext4 /dev/sdb rw,errors=remount-ro',
  String.raw`31 24 0:42 / /mnt/c rw,noatime - 9p C:\134 rw,dirsync,aname=drvfs;path=C:\134;uid=1000`,
  String.raw`32 24 0:43 / /mnt/shared\040drive rw,noatime - drvfs D:\134 rw`,
].join('\n')

const wslProbe = {
  platform: 'linux' as NodeJS.Platform,
  environment: { WSL_DISTRO_NAME: 'Ubuntu' },
  kernelRelease: '6.6.87.2-microsoft-standard-WSL2',
  containerized: false,
  mountInfo: WSL_MOUNT_INFO,
  existsSync: (candidate: string) =>
    ['/', '/home', '/mnt/c', '/mnt/shared drive'].includes(candidate),
  realpathSync: (candidate: string) => candidate,
  mountIdForPath: (candidate: string) => {
    if (candidate.startsWith('/mnt/shared drive')) return '32'
    if (candidate.startsWith('/mnt/c')) return '31'
    return '24'
  },
}

describe('Analyzer WSL filesystem contract', () => {
  test('parses escaped mount points and DrvFS evidence', () => {
    expect(parseLinuxMountInfo(WSL_MOUNT_INFO)).toEqual([
      {
        mountId: '24',
        mountPoint: '/',
        filesystemType: 'ext4',
        source: '/dev/sdb',
        superOptions: 'rw,errors=remount-ro',
      },
      {
        mountId: '31',
        mountPoint: '/mnt/c',
        filesystemType: '9p',
        source: 'C:\\',
        superOptions: String.raw`rw,dirsync,aname=drvfs;path=C:\134;uid=1000`,
      },
      {
        mountId: '32',
        mountPoint: '/mnt/shared drive',
        filesystemType: 'drvfs',
        source: 'D:\\',
        superOptions: 'rw',
      },
    ])
  })

  test.each([
    ['/mnt/c/rikune/workspaces', '/mnt/c (9p)'],
    ['/mnt/shared drive/rikune/storage', '/mnt/shared drive (drvfs)'],
  ])('rejects WSL custody root %s on its longest Windows-backed mount', (root, evidence) => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: root }], wslProbe)
    ).toThrow(evidence)
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: root }], wslProbe)
    ).toThrow(ANALYZER_WSL_FILESYSTEM_ERROR)
  })

  test.each(['9p', 'plan9', 'virtio-plan9', 'virtiofs'])(
    'fails closed on direct WSL2 %s transport even without textual DrvFS options',
    (filesystemType) => {
      const mountPoint = '/mnt/windows'
      const mountInfo = [
        '24 1 8:1 / / rw,relatime - ext4 /dev/sdb rw,errors=remount-ro',
        `33 24 0:44 / ${mountPoint} rw,noatime - ${filesystemType} C: rw`,
      ].join('\n')

      expect(() =>
        assertSupportedAnalyzerFilesystem(
          [{ name: 'workspace.root', path: `${mountPoint}/rikune/workspaces` }],
          {
            ...wslProbe,
            mountInfo,
            existsSync: (candidate) => candidate === '/' || candidate === mountPoint,
            mountIdForPath: () => '33',
          }
        )
      ).toThrow(`${mountPoint} (${filesystemType})`)
    }
  )

  test('accepts WSL custody roots on the canonical Linux filesystem ancestor', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem(
        [
          { name: 'workspace.root', path: '/home/rikune/workspaces' },
          { name: 'api.storageRoot', path: '/home/rikune/storage' },
        ],
        wslProbe
      )
    ).not.toThrow()
  })

  test('checks a symlinked existing ancestor instead of trusting the configured prefix', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'cache.root', path: '/safe/link/cache' }], {
        ...wslProbe,
        existsSync: (candidate) => candidate === '/safe/link' || candidate === '/',
        realpathSync: (candidate) => (candidate === '/safe/link' ? '/mnt/c/rikune' : candidate),
      })
    ).toThrow('/mnt/c (9p)')
  })

  test('fails closed when WSL mount evidence cannot identify a root', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/home/rikune' }], {
        ...wslProbe,
        mountInfo: '',
      })
    ).toThrow('Unable to identify the mount for workspace.root')
  })

  test('uses the opened ancestor mount ID for stacked mounts at the same path', () => {
    const stackedMountInfo = [
      '24 1 8:1 / / rw,relatime - ext4 /dev/sdb rw,errors=remount-ro',
      '40 24 0:50 / /home rw,relatime - ext4 /dev/old rw',
      '41 24 0:51 / /home rw,relatime - virtiofs C: rw',
    ].join('\n')

    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/home/rikune' }], {
        ...wslProbe,
        mountInfo: stackedMountInfo,
        mountIdForPath: () => '41',
      })
    ).toThrow('/home (virtiofs)')
  })

  test('does not impose the WSL filesystem boundary on native Linux', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/mnt/c/rikune' }], {
        ...wslProbe,
        environment: {},
        kernelRelease: '6.8.0-generic',
        kernelVersion: 'Linux version 6.8.0-generic',
      })
    ).not.toThrow()
  })

  test('fails closed on WSL1 before accepting a Linux-side root mount', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/home/rikune' }], {
        ...wslProbe,
        kernelRelease: '4.4.0-19041-Microsoft',
        kernelVersion: 'Linux version 4.4.0-19041-Microsoft',
      })
    ).toThrow(ANALYZER_WSL2_REQUIRED_ERROR)
  })

  test('accepts the older microsoft-standard WSL2 kernel identity', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/home/rikune' }], {
        ...wslProbe,
        kernelRelease: '4.19.128-microsoft-standard',
        kernelVersion: 'Linux version 4.19.128-microsoft-standard',
      })
    ).not.toThrow()
  })

  test('leaves Linux-container bind semantics to the secure filesystem helper', () => {
    expect(() =>
      assertSupportedAnalyzerFilesystem([{ name: 'workspace.root', path: '/mnt/c/rikune' }], {
        ...wslProbe,
        containerized: true,
      })
    ).not.toThrow()
  })
})
