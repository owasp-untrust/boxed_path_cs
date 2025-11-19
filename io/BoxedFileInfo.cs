using System;
using System.IO;

namespace Owasp.Untrust.BoxedPath.IO;

/// <summary>
/// Represents a file, securely wrapping System.IO.FileInfo.
/// Does NOT inherit from FileInfo to prevent path leakage.
/// </summary>
public class BoxedFileInfo : BoxedFileSystemInfo
{
    // Constructor uses the base constructor and a cast to initialize InnerInfo
    public BoxedFileInfo(BoxedPath path)
        // CRITICAL: We call ValidateAndExpose() to construct the internal FileInfo, 
        // then pass both the secure path and the FileInfo to the base constructor.
        : base(path, new FileInfo(path.ValidateAndExpose()))
    {
    }

    // Properties specific to files
    public long Length => ((FileInfo)InnerInfo).Length;
    
    public BoxedStreamReader OpenText()
    {
        // Uses the validated path from the base object to ensure a valid stream open
        return new BoxedStreamReader(BoxedPath);
    }
}
