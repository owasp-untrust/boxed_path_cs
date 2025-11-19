namespace Owasp.Untrust.BoxedPath; // File-Scoped Namespace

// C# 10 File-Scoped Namespace
public enum SandboxJailbreak
{
    // Disallows path traversal using symlinks (default and most secure)
    DISALLOW,
    
    // Allows paths that are lexically within the sandbox, but ignores symlink checks
    UNCHECKED_SYMLINKS 
}
