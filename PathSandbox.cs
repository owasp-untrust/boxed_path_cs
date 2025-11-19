using System.IO;
using Owasp.Untrust.BoxedPath;
using Owasp.Untrust.BoxedPath.Internal;

namespace Owasp.Untrust.BoxedPath;

public record PathSandbox
{
    private const int DEFAULT_MAX_LINK_FOLLOWS = 5;
    private const SandboxJailbreak DEFAULT_SANDBOX_JAILBREAK_POLICY = SandboxJailbreak.DISALLOW;

    // Properties are initialized via the primary constructor
    internal string SandboxRootAbsolutePath { get; }
    public SandboxJailbreak JailbreakPolicy { get; }
    public int MaxLinkFollows { get; }

    // Static Factory Methods (BoxRoot overloads) ... (unchanged)
    public static PathSandbox BoxRoot(string rootPath, SandboxJailbreak jailbreakPolicy = DEFAULT_SANDBOX_JAILBREAK_POLICY, int maxLinkFollows = DEFAULT_MAX_LINK_FOLLOWS)
    {
        return new PathSandbox(rootPath, jailbreakPolicy, maxLinkFollows);
    }
    public static PathSandbox BoxRoot(SandboxJailbreak jailbreakPolicy, string rootPath, int maxLinkFollows = DEFAULT_MAX_LINK_FOLLOWS)
    {
        return new PathSandbox(rootPath, jailbreakPolicy, maxLinkFollows);
    }
    public static PathSandbox BoxRoot(string first, params string[] more)
    {
        string fullPath = Path.Combine(first, Path.Combine(more));
        return BoxRoot(fullPath);
    }
    public static PathSandbox BoxRoot(SandboxJailbreak jailbreakPolicy, string first, params string[] more)
    {
        string fullPath = Path.Combine(first, Path.Combine(more));
        return BoxRoot(fullPath, jailbreakPolicy);
    }

    public static PathSandbox BoxRoot(SandboxJailbreak jailbreakPolicy, int maxLinkFollows, string first, params string[] more)
    {
        string fullPath = Path.Combine(first, Path.Combine(more));
        return BoxRoot(fullPath, jailbreakPolicy, maxLinkFollows);
    }

    private PathSandbox(string rootPath, SandboxJailbreak jailbreakPolicy, int maxLinkFollows)
    {
        JailbreakPolicy = jailbreakPolicy;
        // NOTE: Must trim any trailing slash/backslash or the later tests of StartsWith might fail due to the tested path NOT having a trailing slash/backslash
        SandboxRootAbsolutePath = Path.GetFullPath(rootPath).TrimEnd(Path.DirectorySeparatorChar);
        MaxLinkFollows = maxLinkFollows;
    }

    // Path Creation Methods (of / resolve) ... (unchanged)
    public BoxedPath Of(string path)
    {
        string combinedPath = Path.Combine(SandboxRootAbsolutePath, path);
        return BoxedPath.Of(this, combinedPath);
    }
    public BoxedPath Of(string first, params string[] more)
    {
        string path = Path.Combine(first, Path.Combine(more));
        return Of(path);
    }
    public BoxedPath Combine(string relativePath)
    {
        return GetRoot().Combine(relativePath);
    }
    public BoxedPath GetRoot()
    {
        return new BoxedAbsolute(this, SandboxRootAbsolutePath);
    }
}
