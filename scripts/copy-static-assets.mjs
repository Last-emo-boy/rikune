#!/usr/bin/env node

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DIST_ROOT = path.join(ROOT, 'dist')

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true })
}

function copyFile(source, target) {
  ensureDir(path.dirname(target))
  fs.copyFileSync(source, target)
}

function copyDirectoryRecursive(source, target) {
  if (!fs.existsSync(source)) {
    return
  }

  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name)
    const targetPath = path.join(target, entry.name)
    if (entry.isDirectory()) {
      copyDirectoryRecursive(sourcePath, targetPath)
      continue
    }
    copyFile(sourcePath, targetPath)
  }
}

function copyDashboardAssets() {
  copyDirectoryRecursive(
    path.join(ROOT, 'src', 'api', 'dashboard'),
    path.join(DIST_ROOT, 'api', 'dashboard')
  )
}

function copyPluginScripts() {
  const pluginsRoot = path.join(ROOT, 'src', 'plugins')
  if (!fs.existsSync(pluginsRoot)) {
    return
  }

  for (const pluginId of fs.readdirSync(pluginsRoot, { withFileTypes: true })) {
    if (!pluginId.isDirectory()) {
      continue
    }
    const scriptsDir = path.join(pluginsRoot, pluginId.name, 'scripts')
    if (!fs.existsSync(scriptsDir)) {
      continue
    }
    copyDirectoryRecursive(
      scriptsDir,
      path.join(DIST_ROOT, 'resources', 'scripts', pluginId.name)
    )
  }
}

copyDashboardAssets()
copyPluginScripts()
