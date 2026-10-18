export function assertDarwin(platform) {
  if (platform !== 'darwin') throw new Error('M2 requires Darwin; no measurement was started')
}

export function options(env) {
  const value = env.M2_REPEATS ?? '3'
  if (!/^[1-9]\d*$/.test(value) || Number(value) > 10) throw new Error('M2_REPEATS must be an integer from 1 to 10')
  const parts = (env.M2_PARTS ?? '1,2').split(',')
  if (parts.some((p) => p !== '1' && p !== '2') || new Set(parts).size !== parts.length) throw new Error('M2_PARTS must contain distinct parts 1 and/or 2')
  return { repeats: Number(value), parts }
}

export const shellQuote = (text) => "'" + String(text).replaceAll("'", "'\\''") + "'"

export function wrapperText(configPath, executable, script) {
  return `#!/bin/sh\nFIXTURE_CONFIG=${shellQuote(configPath)} exec ${shellQuote(executable)} ${shellQuote(script)} "$@"\n`
}
