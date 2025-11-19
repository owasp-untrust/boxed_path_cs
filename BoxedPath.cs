using System;
using System.IO;
using System.Security;
using Owasp.Untrust.BoxedPath.Internal;

namespace Owasp.Untrust.BoxedPath;

public abstract record BoxedPath
{
    // --- Static Methods (Path.Combine etc. replacement) ---

    public static BoxedPath Of(PathSandbox sandbox, string path)
    {
        // Path.IsPathRooted determines if it's absolute (C:, /)
        if (Path.IsPathRooted(path))
        {
            return new BoxedAbsolute(sandbox, path);
        }
        else
        {
            return new BoxedRelative(sandbox, path);
        }
    }
    
    public static BoxedPath Combine(BoxedPath path, string other)
    {
        return path.Combine(other);
    }
    public static BoxedPath Combine(BoxedPath path, params string[] more)
    {
        return path.Combine(more);
    }

    // Equivalent to: Path.GetDirectoryName(string)
    public static BoxedPath? GetDirectoryName(BoxedPath path)
    {
        try {
            return path.Parent;
        }
        catch (Exception) {
            return null;
        }
    }

    // Equivalent to: Path.GetExtension(string)
    public static string GetExtension(BoxedPath path)
    {
        // Returns the extension of the file or an empty string if none.
        return Path.GetExtension(path.UnsecuredPathString) ?? string.Empty;
    }

    // Equivalent to: Path.GetFileName(string)
    // Note: This duplicates the instance method GetFileName(), but is added for completeness.
    public static string GetFileName(BoxedPath path)
    {
        // Returns the file name and extension (or directory name if no trailing slash).
        return path.GetFileName();
    }

    // Equivalent to: Path.GetFileNameWithoutExtension(string)
    public static string GetFileNameWithoutExtension(BoxedPath path)
    {
        // Returns the file name without the extension.
        return Path.GetFileNameWithoutExtension(path.UnsecuredPathString) ?? string.Empty;
    }

    // Equivalent to: Path.IsPathRooted(string)
    public static bool IsPathRooted(BoxedPath path)
    {
        // Returns true if the path is absolute.
        return Path.IsPathRooted(path.UnsecuredPathString);
    }

    // Equivalent to: Path.ChangeExtension(string, string)
    // IMPORTANT: This must return a new BoxedPath instance to ensure validation.
    public static BoxedPath ChangeExtension(BoxedPath path, string? extension)
    {
        // Path.ChangeExtension simply returns a string.
        string newPathString = Path.ChangeExtension(path.UnsecuredPathString, extension);
        
        // Return a new BoxedPath instance, triggering the security validation.
        return path.PartiallyModified(newPathString);
    }

    protected readonly string UnsecuredPathString;
    public PathSandbox Sandbox { get; }

    protected BoxedPath(PathSandbox sandbox, string path)
    {
        Sandbox = sandbox;
        UnsecuredPathString = path;
    }
    
    // --- Security Implementation Methods ---

    protected static string ResolveAndValidate(PathSandbox sandbox, string absolutePath)
    {
        if (sandbox.JailbreakPolicy == SandboxJailbreak.DISALLOW)
        {
            return DeepResolveAndValidate(sandbox.SandboxRootAbsolutePath, sandbox.MaxLinkFollows, absolutePath);
        }

        ShallowValidate(sandbox.SandboxRootAbsolutePath, absolutePath);
        return absolutePath;
    }

    // 1. Lexical Path Traversal Check
    protected static void ShallowValidate(string sandboxAbsolute, string absolutePath)
    {
        if (!absolutePath.StartsWith(sandboxAbsolute, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException($"Path '{absolutePath}' is outside the sandbox '{sandboxAbsolute}' (Lexical Check Failed)");
        }
    }

    // 2. Physical Path Traversal Check (Symlink/Hard Link Check)
    protected static string DeepResolveAndValidate(string sandboxAbsolute, int maxFollowLinks, string absolutePath)
    {
        // 1. Get the components of the path relative to the root.
        string relativePath = Path.GetRelativePath(sandboxAbsolute, absolutePath);
        int remainingLinkFollows = maxFollowLinks;

        string[] segments = relativePath.Split(
            Path.DirectorySeparatorChar, 
            StringSplitOptions.RemoveEmptyEntries
        );

        string currentPhysicalPath = sandboxAbsolute;

        int segmentIdx = 0;
        for ( ; segmentIdx < segments.Length ; ++segmentIdx)
        {
            string curSegment = segments[segmentIdx];

            string pathBeforeFollowingLinks = Path.GetFullPath(Path.Combine(currentPhysicalPath, curSegment));
            // CRITICAL JAILBREAK CHECK - BEFORE RESOLVING LINK
            if (!pathBeforeFollowingLinks.StartsWith(sandboxAbsolute, StringComparison.OrdinalIgnoreCase))
            {
                if (absolutePath.Equals(pathBeforeFollowingLinks))
                {
                    throw new SecurityException(
                        $"Path '{absolutePath}' resolves outside the sandbox (Jailbreak detected)."
                    );
                }
                else
                {
                    throw new SecurityException(
                        $"Path '{pathBeforeFollowingLinks}' (derived from rebuilding {absolutePath}) resolves outside the sandbox (Jailbreak detected)."
                    );
                }
            }

            string currentCandidate = pathBeforeFollowingLinks;
            try
            {
                while (new DirectoryInfo(currentCandidate).ResolveLinkTarget(false) is FileSystemInfo linkInfo) // recursive link following
                {
                    // --- DEPTH LIMIT CHECK (Uses the configurable policy) ---
                    --remainingLinkFollows;
                    if (remainingLinkFollows < 0)
                    {
                        throw new SecurityException(
                            $"Symlink depth limit exceeded. Aborting traversal after {maxFollowLinks} links (Policy violation)."
                        );
                    }
                    // ---------------------------------------------------------

                    string linkTarget = linkInfo.FullName;
                    string linkParent = Path.GetDirectoryName(currentCandidate)!;
                    string? resolvedTarget = Path.IsPathRooted(linkTarget)
                        ? linkTarget
                        : Path.GetFullPath(Path.Combine(linkParent, linkTarget));

                    // CRITICAL JAILBREAK CHECK - AFTER RESOLVING LINK
                    if (!resolvedTarget.StartsWith(sandboxAbsolute, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new SecurityException(
                            $"Path '{resolvedTarget}' (derived from recursively following of symlink {pathBeforeFollowingLinks}) resolves outside the sandbox (Jailbreak detected)."
                        );
                    }

                    currentCandidate = resolvedTarget;
                }

                currentPhysicalPath = currentCandidate;
            }
            catch (IOException)
            {
                // concat the rest of the segments
                currentPhysicalPath = currentCandidate;
                for (++segmentIdx ; segmentIdx < segments.Length ; ++segmentIdx)
                {
                    currentPhysicalPath = Path.Combine(currentPhysicalPath, segments[segmentIdx]);
                }
                break; 
            }
            catch (UnauthorizedAccessException)
            {
                throw new SecurityException($"Access denied when inspecting path '{currentCandidate}' (link resolution might be recursive. Started with {pathBeforeFollowingLinks}).");
            }
        }

        return currentPhysicalPath;
    }

    // --- Path String Access ---
    // Provides the full, actual path string. The explicit naming discourages accidental use.
    public string ToUncheckedAndUnsecuredString() => UnsecuredPathString;

    public abstract string ValidateAndExpose();

    // --- Masked String Representation ---
    // Implements the requested masking logic for logging and display.
    public override string ToString()
    {
        string root = Sandbox.SandboxRootAbsolutePath;
        string path = UnsecuredPathString;

        // 1. Exception: If the path IS the sandbox root, return only the token.
        if (string.Equals(path, root, StringComparison.OrdinalIgnoreCase))
        {
            return "[SANDBOX_ROOT]";
        }

        // 2. Get the path relative to the root. This strips the common prefix.
        // E.g., C:\Sandbox\Data\File.txt -> Data\File.txt
        // Path.GetRelativePath is available in .NET 8.
        string relativePath = Path.GetRelativePath(root, path);

        // 3. Get the last segment (file or folder name) of the relative path.
        // E.g., Data\File.txt -> File.txt | Data -> Data
        string lastSegment = Path.GetFileName(relativePath);

        if (string.IsNullOrEmpty(lastSegment))
        {
            // Fallback for tricky normalized paths (e.g., if it's just '.\')
            lastSegment = relativePath;
        }

        // 4. Construct the masked string.
        return $"[SANDBOX_ROOT]...{lastSegment}";
    }



    // --- Instance Methods ---

    public BoxedPath Combine(string other)
    {
        string newPathString = Path.Combine(UnsecuredPathString, other);
        return this.PartiallyModified(newPathString); 
    }
    public BoxedPath Combine(params string[] more)
    {
        string newPathString = Path.Combine(UnsecuredPathString, Path.Combine(more));
        return this.PartiallyModified(newPathString); 
    }

    public string GetFileName() => Path.GetFileName(UnsecuredPathString) ?? string.Empty;
    
    public BoxedPath? Parent {
        get {
            string? parentPath = Path.GetDirectoryName(UnsecuredPathString);
            if (parentPath == null || /*it's its own parent - aka a root */ string.Equals(parentPath, UnsecuredPathString, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }
            return this.PartiallyModified(parentPath);
        }
    }

    public bool IsAbsolute() => Path.IsPathRooted(UnsecuredPathString);
    public BoxedPath FullPath {
        get { return new BoxedAbsolute(Sandbox, Path.Combine(Sandbox.SandboxRootAbsolutePath, UnsecuredPathString)); } 
    }

    protected abstract BoxedPath PartiallyModified(string newPath); 
}
