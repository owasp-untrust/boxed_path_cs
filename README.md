# Owasp.Untrust.BoxedPath (.NET)

![Build Status](https://img.shields.io/github/actions/workflow/status/owasp-untrust/boxed_path_cs/build.yml?branch=main)
[![NuGet](https://img.shields.io/nuget/v/Owasp.Untrust.BoxedPath)](https://www.nuget.org/packages/Owasp.Untrust.BoxedPath)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

A secure path management library for .NET designed to prevent Directory Traversal (Path Traversal) and Symbolic Link (Symlink) Jailbreak attacks. It provides a robust "sandbox" mechanism to ensure that all file system operations remain strictly within a defined root directory.

## The Need

Modern .NET applications frequently interact with the file system. However, accepting file paths from untrusted sources (user input, uploads, configuration files) introduces critical security risks:

* **Directory Traversal:** Attackers using `../` sequences to access sensitive system files (e.g., `../../windows/system32/config/SAM`).
* **Symlink Jailbreak:** Attackers using symbolic links (symlinks) to trick the application into reading or writing files outside the intended directory, even if the path *looks* safe lexically.
* **TOCTOU Vulnerabilities:** Time-of-Check to Time-of-Use race conditions where a path is validated but then swapped (e.g., via symlink) before it is used.

Standard .NET classes like `System.IO.Path` provide lexical manipulation but do not enforce security boundaries or handle advanced symlink resolution securely.

## The Solution

`Owasp.Untrust.BoxedPath` introduces two core concepts:

1.  **`PathSandbox`**: Defines the secure root directory and the security policy (e.g., whether symlinks are allowed).
2.  **`BoxedPath`**: An immutable, secure wrapper around a file path. It guarantees that the path it holds has been validated to be inside its associated sandbox.

All operations on `BoxedPath` (like `Combine`, `GetParent`) return a new, validated `BoxedPath` or throw a `SecurityException` if the operation would result in a path outside the sandbox.

## Key Features

* **Strict Sandboxing:** Enforces that all paths must resolve to a location inside the sandbox root.
* **Symlink Defense:** Offers a robust, component-by-component path traversal algorithm (`ResolveAndValidatePath`) that physically resolves symlinks to prevent jailbreaks.
* **TOCTOU Protection:** Validation resolves the *physical* path, ensuring that the path used for I/O is the same one that was checked.
* **Drop-in API Feel:** Designed to mimic the `System.IO.Path` and `FileInfo` APIs for ease of adoption.
* **Secure Wrappers:** Provides `BoxedFileInfo`, `BoxedDirectoryInfo`, and `BoxedFileStream` to perform I/O operations safely without exposing the raw path.

## Installation

Install via NuGet:

```bash
dotnet add package Owasp.Untrust.BoxedPath
```

## Usage

### 1. Initialization

Create a `PathSandbox` instance to define your secure root.

```csharp
using Owasp.Untrust.BoxedPath;

// Define a sandbox rooted at "C:\Safe\Uploads"
// Default policy: DISALLOW (Symlinks are followed but must stay inside the sandbox)
PathSandbox sandbox = PathSandbox.BoxRoot(@"C:\Safe\Uploads");
```

### 2. Creating Secure Paths

Use the `Of()` factory method to create a `BoxedPath` from an untrusted string.

```csharp
try
{
    // User input: "user_data.txt" (Safe)
    BoxedPath safePath = BoxedPath.Of(sandbox, "user_data.txt");
    
    // User input: "../../../windows/system.ini" (Malicious)
    // THROWS SecurityException immediately!
    BoxedPath maliciousPath = BoxedPath.Of(sandbox, "../../../windows/system.ini");
}
catch (SecurityException ex)
{
    Console.WriteLine($"Attack blocked: {ex.Message}");
}
```

### 3. Path Manipulation

Combine paths securely. The library ensures the result is still valid.

```csharp
BoxedPath basePath = BoxedPath.Of(sandbox, "users");

// Safe combination: C:\Safe\Uploads\users\alice
BoxedPath userPath = BoxedPath.Combine(basePath, "alice"); 

// Malicious combination attempt
// THROWS SecurityException
BoxedPath hackAttempt = BoxedPath.Combine(basePath, "../../admin"); 
```

### 4. Performing File I/O

**Crucial:** Do not convert the `BoxedPath` to a string to use standard `File` methods directly, as that breaks the chain of trust. Instead, use the secure wrappers or the `ValidateAndExpose()` method at the very last moment.

#### Option A: Use Secure Wrappers (Recommended)

```csharp
// Check existence safely
if (BoxedFile.Exists(safePath)) 
{
    // Read text securely
    string content = BoxedFile.ReadAllText(safePath);
}

// Use FileInfo wrapper (Does NOT expose .FullName)
var fileInfo = new BoxedFileInfo(safePath);
long size = fileInfo.Length;

// Secure FileStream
using (var stream = new BoxedFileStream(safePath, FileMode.Open))
{
    // ... read/write ...
}
```

#### Option B: Explicit Exposure (Use with Caution)

If you must use an API that strictly requires a `string` path:

```csharp
// ValidateAndExpose re-runs checks and returns the raw physical path string.
// Use this result IMMEDIATELY and do not store it.
string rawPath = safePath.ValidateAndExpose(); 

System.IO.File.Delete(rawPath);
```

## Advanced Configuration

### Symlink Policy

You can control how symbolic links are handled.

```csharp
// Default: Follows symlinks, but throws if the target is outside the sandbox.
var secureSandbox = PathSandbox.BoxRoot("/data", SandboxJailbreak.DISALLOW);

// Dangerous: Allows symlinks to point anywhere (relies on OS permissions).
var looseSandbox = PathSandbox.BoxRoot("/data", SandboxJailbreak.UNCHECKED_SYMLINKS);
```

### Max Link Depth

To prevent infinite loops or Denial of Service (DoS) via "symlink bombs," you can limit the recursion depth.

```csharp
// Limit to 20 link hops (Default is 10)
var deepSandbox = PathSandbox.BoxRoot("/data", SandboxJailbreak.DISALLOW, maxLinkFollows: 20);
```

## Contributing

This project is an official OWASP contribution. Issues and Pull Requests are welcome on the [GitHub Repository](https://github.com/owasp-untrust/boxed_path_cs).

## License

Licensed under the **Apache License 2.0**.
