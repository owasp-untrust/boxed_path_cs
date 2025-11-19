using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Secure wrapper for System.IO.FileStream, using inheritance for cleaner code.
/// </summary>
public class BoxedFileStream : FileStream
{
    // Ctor accepts BoxedPath and delegates to the base FileStream ctor
    public BoxedFileStream(BoxedPath path, FileMode mode, FileAccess access = FileAccess.ReadWrite, FileShare share = FileShare.None)
        // CRITICAL: Call ValidateAndExpose() before passing the path to the base constructor
        : base(path.ValidateAndExpose(), mode, access, share)
    {
        // No body required; the base ctor does all the work.
    }
}
