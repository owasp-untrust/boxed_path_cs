using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Secure wrapper for System.IO.StreamReader, using inheritance.
/// </summary>
public class BoxedStreamReader : StreamReader
{
    // Ctor accepts BoxedPath and delegates to the base StreamReader ctor
    public BoxedStreamReader(BoxedPath path) 
        // CRITICAL: Call ValidateAndExpose() before passing the path to the base constructor
        : base(path.ValidateAndExpose())
    {
    }
}
