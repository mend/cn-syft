# JavaScript Bundled Package Detection

## Overview

The JavaScript cataloger has been enhanced to detect bundled packages with accurate versions from frameworks like Next.js and Vite, including support for npm aliases.

## Problem Solved

**Before:** Bundled packages were detected but with missing or incorrect versions:
- `send@unknown` 
- `react@missing-version`
- npm aliased packages like `webpack-sources1` were not detected

**After:** Bundled packages now have accurate versions from the bundler's devDependencies:
- `send@0.18.0` (from Next.js devDependencies)
- `react@18.2.0` (from Vite devDependencies)
- `webpack-sources@1.4.3` (from npm alias `"webpack-sources1": "npm:webpack-sources@1.4.3"`)
- `webpack-sources@3.2.3` (from npm alias `"webpack-sources3": "npm:webpack-sources@3.2.3"`)

## How It Works

### Detection Process

1. **Path Analysis**: When parsing a `package.json` file, the cataloger checks if it's in a bundler's dist directory:
   ```
   ✅ /app/node_modules/next/dist/package.json
   ✅ /app/node_modules/vite/dist/package.json  
   ❌ /app/node_modules/lodash/package.json (not a bundler)
   ```

2. **Parent Resolution**: Finds the bundler's main package.json:
   ```
   From: /app/node_modules/next/dist/compiled/send/package.json
   To:   /app/node_modules/next/package.json
   ```

3. **Version Extraction**: Reads the bundler's `devDependencies` for accurate versions:
   ```json
   {
     "devDependencies": {
       "send": "^0.18.0",
       "react": "^18.2.0",
       "webpack-sources1": "npm:webpack-sources@1.4.3",
       "webpack-sources3": "npm:webpack-sources@3.2.3",
       "loader-utils2": "npm:loader-utils@2.0.0"
     }
   }
   ```

4. **Package Creation**: Creates bundled packages with correct versions, including npm aliased packages.

## Supported Bundlers

Currently supports these bundlers with their specific path patterns:

| Bundler | Path Pattern | Example |
|---------|-------------|---------|
| **Next.js** | `node_modules/next/dist/` | `/app/node_modules/next/dist/compiled/send/package.json` |
| **Vite** | `node_modules/vite/dist/` | `/app/node_modules/vite/dist/client/package.json` |

## Implementation Details

### Key Features

- **Cross-Platform**: Works on Windows, macOS, and Linux
- **NPM Alias Support**: Detects npm aliased packages like `"webpack-sources1": "npm:webpack-sources@1.4.3"`
- **Multiple Versions**: Supports multiple versions of the same package (e.g., `webpack-sources@1.4.3` and `webpack-sources@3.2.3`)
- **Minimal & Focused**: Simple detection logic for accuracy
- **Performance**: Efficient path parsing and JSON processing with early returns

### Code Structure

```go
// Main detection function
updateVersionsFromBundlerDevDependencies()

// Helper functions
parseBundlerPath()     // Detects bundler and returns parent path
loadPackageJSON()      // Reads package.json consistently  
parseNpmAlias()        // Parses npm alias format: "npm:package@version"
```

## Example Scenario

```
Project Structure:
├── node_modules/
│   └── next/
│       ├── package.json          ← Contains devDependencies
│       └── dist/
│           └── compiled/
│               └── send/
│                   └── package.json  ← Being parsed
```

**Result:**
1. Detects `/node_modules/next/dist/` pattern → Next.js bundler
2. Reads `/node_modules/next/package.json` devDependencies  
3. Updates bundled package: `send@0.18.0` (from Next.js devDependencies)

## NPM Alias Example

```
Project Structure:
├── node_modules/
│   └── next/
│       ├── package.json          ← Contains devDependencies with npm aliases
│       └── dist/
│           └── compiled/
│               ├── webpack-sources1/
│               │   └── package.json  ← name: "webpack-sources", version: ""
│               └── webpack-sources3/
│                   └── package.json  ← name: "webpack-sources", version: ""
```

**Parent devDependencies:**
```json
{
  "devDependencies": {
    "webpack-sources1": "npm:webpack-sources@1.4.3",
    "webpack-sources3": "npm:webpack-sources@3.2.3"
  }
}
```

**Result:**
1. Detects folder name `webpack-sources1` in devDependencies
2. Parses npm alias `"npm:webpack-sources@1.4.3"` → version `1.4.3`
3. Updates package: `webpack-sources@1.4.3`
4. Similarly for `webpack-sources3` → `webpack-sources@3.2.3`

## Benefits

- **Accurate SBOMs**: Bundled packages now have correct versions including npm aliases
- **Better Security**: Accurate versions enable proper vulnerability scanning  
- **Multiple Versions**: Detects when bundlers include multiple versions of the same package
- **Compliance**: More complete dependency tracking for audits
- **Visibility**: See what's actually bundled in your application, including aliased dependencies

## Technical Notes

- Updates existing packages with correct versions from bundler devDependencies
- Supports npm alias format: `"alias-name": "npm:real-package@version"`
- Uses regex pattern matching for reliable npm alias parsing
- Cross-platform compatible (Windows, macOS, Linux)
- Early return optimization for better performance
- Minimal implementation focused on Next.js and Vite (most common bundlers)
- Easy to extend for additional bundlers or alias formats when needed
