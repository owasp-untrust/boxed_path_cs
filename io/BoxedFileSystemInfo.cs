using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Base class for BoxedFileInfo and BoxedDirectoryInfo.
/// Encapsulates the BoxedPath and delegates common properties.
/// This class does NOT inherit from System.IO.FileSystemInfo.
/// </summary>
public abstract class BoxedFileSystemInfo
{
    // These fields hold the necessary information for delegation and validation
    protected readonly FileSystemInfo InnerInfo;
    protected readonly BoxedPath BoxedPath;

    // The base constructor requires the BoxedPath and the underlying FileSystemInfo
    protected BoxedFileSystemInfo(BoxedPath path, FileSystemInfo innerInfo)
    {
        // The path must already be validated and exposed before this constructor is called.
        this.BoxedPath = path;
        this.InnerInfo = innerInfo;
    }

    // Common properties delegated from the inner System.IO object
    public virtual string Name => InnerInfo.Name;
    public virtual bool Exists => InnerInfo.Exists;
    public virtual DateTime CreationTimeUtc => InnerInfo.CreationTimeUtc;
    public virtual DateTime LastWriteTimeUtc => InnerInfo.LastWriteTimeUtc;
    
    // Securely exposes the full path via the BoxedPath property (not a string)
    public BoxedPath FullPath => BoxedPath.FullPath;

    // Securely exposes the parent directory via a BoxedDirectoryInfo wrapper
    public BoxedDirectoryInfo? Parent
    {
        get
        {
            // Use the GetParent method on the BoxedPath to ensure safety
            var parentPath = BoxedPath.Parent;
            
            if (parentPath is null) return null;

            // Re-wrap the secure parent path
            return new BoxedDirectoryInfo(parentPath);
        }
    }
}
