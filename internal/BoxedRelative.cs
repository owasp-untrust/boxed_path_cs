using System.IO;
using System.Security;

namespace Owasp.Untrust.BoxedPath.Internal;

/// <summary>
/// Handles relative paths. Stores the raw string and validates on Egress.
/// </summary>
internal sealed record BoxedRelative : BoxedPath
{
    public BoxedRelative(PathSandbox sandbox, string relativePath) 
    : base(sandbox, relativePath)
    {
    }

    public override string ValidateAndExpose()
    {
        string fullPath = Path.Combine(Sandbox.SandboxRootAbsolutePath, UnsecuredPathString);
        return ResolveAndValidate(Sandbox, fullPath); 
    }


    protected override BoxedPath PartiallyModified(string newPath)
    {
        return new BoxedRelative(Sandbox, newPath);
    }
}
