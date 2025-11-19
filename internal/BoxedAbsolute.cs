using System.IO;
using System.Security;

namespace Owasp.Untrust.BoxedPath.Internal;

/// <summary>
/// Handles absolute paths. Validation is performed once at construction (Ingress).
/// </summary>
internal sealed record BoxedAbsolute : BoxedPath
{
    public BoxedAbsolute(PathSandbox sandbox, string absolutePath) 
    : base(sandbox, ResolveAndValidate(sandbox, absolutePath))
    {
    }
    
    public override string ValidateAndExpose()
    {
        // For absolute paths, validation passed on ingress. 
        return UnsecuredPathString;
    }

    protected override BoxedPath PartiallyModified(string newPath)
    {
        return new BoxedAbsolute(Sandbox, newPath);
    }
}
