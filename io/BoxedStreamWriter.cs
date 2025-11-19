using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Secure wrapper for System.IO.StreamWriter, using inheritance.
/// </summary>
public class BoxedStreamWriter : StreamWriter
{
    // Ctor accepts BoxedPath and delegates to the base StreamWriter ctor
    public BoxedStreamWriter(BoxedPath path) 
        // CRITICAL: Call ValidateAndExpose() before passing the path to the base constructor
        : base(path.ValidateAndExpose())
    {
    }
}
