import { execSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectDir = path.join(__dirname);

console.log('Running tests from:', projectDir);

try {
  const result = execSync(
    `npm test -- tests/unit/frida-script-inject.test.ts tests/unit/frida-runtime-instrument.test.ts tests/unit/frida-trace-capture.test.ts tests/unit/setup-guidance.test.ts`,
    {
      cwd: projectDir,
      encoding: 'utf8',
      stdio: 'inherit',
    }
  );
  console.log('Tests completed successfully');
  process.exit(0);
} catch (error) {
  console.error('Tests failed:', error.message);
  process.exit(error.status || 1);
}
