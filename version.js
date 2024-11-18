const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const packageJsonPath = path.resolve(__dirname, 'package.json');
const { version } = require(packageJsonPath);

let commitHash = 'unknown';
try {
    commitHash = execSync('git rev-parse HEAD').toString().trim();
} catch (err) {
    console.error('Failed to get Git commit hash:', err.message);
}

// Write the commit hash to a file
const outputPath = path.resolve('.', 'src', 'version.ts');
const content = `
    export const GIT_COMMIT_HASH = '${commitHash}';
    export const APP_VERSION = '${version}';
    `;

fs.writeFileSync(outputPath, content, { encoding: 'utf8' });

console.log(`Git commit hash written to ${outputPath}`);
